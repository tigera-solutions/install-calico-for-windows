# Provision k8s environment in AWS

These instructions provide configuration example of a k8s cluster using AWS infrastructure. This guide assumes that Calico CNI is used for networking. For other networking options refer to [official documentation](https://docs.tigera.io/getting-started/windows-calico/).

## provision cluster infrastructure with terraform

Use [terraform](https://www.terraform.io/downloads.html) to initialize the project and provision the infrastructure in AWS.

Before executing terraform commands, configure variables in `terraform.tfvars` file:

- `key_name` - name for EC2 KeyPair that will be created in AWS and used with EC2 instances
- `aws_region` - AWS region to provision resources in. Default: `us-west-2`
- `pull_secret_json_path` - path to JSON file containing Tigera pull secret
- `calico_license_path` - path to Calico Enterprise license file
- `resource_prefix` - prefix that will be added to all provisioned resources names. Default: `cali4win-`

>If you use AWS region different from default `us-west-2`, you will need to adjust AMI variables specified in `variables.tf`.

Review `variables.tf` to adjust any other variables.

```bash
cd ./cluster/aws
terraform init
# run terraform plan
terraform plan
# create infrastructure
terraform apply
```

## launch k8s cluster and join Linux workers

`SSH` into the master node and initialize k8s control plane. You can use `/home/ubuntu/setup/1-kubeadm-init-config.yaml` file that contains example configuration for k8s cluster.

```bash
MASTER0_IP='xx.xx.xx.xx' # set master node public IP in your local shell
SSH_KEY='./private_key.pem'
ssh -i $SSH_KEY -o IdentitiesOnly=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$MASTER0_IP

######################################################
# commands below should be executed on the master node
######################################################
# pre-pull images if needed
sudo kubeadm config images pull
# launch k8s cluster
sudo kubeadm init --config setup/1-kubeadm-init-config.yaml
# run suggested commands from kubeadm init output
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# get certificate hash and join token to use with kubeadm join command on worker nodes
CERT_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')
# get CA cert hash to use when joining worker nodes
echo "TOKEN_CERT_HASH=sha256:$CERT_HASH"
# get join token
echo "JOIN_TOKEN=$(sudo kubeadm token list -o jsonpath='{.token}')"
```

SSH into each Linux worker node and join it to the control plane, i.e. master node

```bash
#######################################################
# commands below should be executed on each worker node
#######################################################
# set JOIN_TOKEN and TOKEN_CERT_HASH variables retrieved from the master node
# then use them to replace tokens in the setup/1-kubeadm-join-config.yaml
sed -e "s/\$JOIN_TOKEN/$JOIN_TOKEN/g" -e "s/\$TOKEN_CERT_HASH/$TOKEN_CERT_HASH/g" setup/1-kubeadm-join-config.yaml > kubeadm-join.yaml
# join worker to the control plane
sudo kubeadm join --config kubeadm-join.yaml
```

Once all Linux workers are joined to the control plane, you should have one master node and four worker nodes. You can validate it by running the following command on the master node:

```bash
# get cluster nodes
kubectl get node
```

## install and configure Calico Enterprise

Before Windows workers can be joined to the cluster, Calico Enterprise needs to be installed and configured. If Calico CNI is used for networking, you should configure either BGP or VXLAN backend as that's the only options Windows hosts can work with. Refer to [Quickstart guide](https://docs.tigera.io/getting-started/kubernetes/quickstart#install-calico-enterprise) for official installation steps.

Install Calico Enterprise from the master host or from your local shell if you configured your local shell to connect to the cluster.

Create the storage class

```bash
kubectl create -f ~/setup/2-ebs-storageclass.yaml
```

Deploy Calico and Prometheus operators

```bash
# calico operator
kubectl create -f https://docs.tigera.io/manifests/tigera-operator.yaml
# prometheus operator
kubectl create -f https://docs.tigera.io/manifests/tigera-prometheus-operator.yaml
```

Configure Tigera pull secret

```bash
kubectl create secret generic tigera-pull-secret \
    --from-file=.dockerconfigjson=setup/pull-secret.json \
    --type=kubernetes.io/dockerconfigjson -n tigera-operator
```

>Set Calico networking backend to either BGP or VXLAN. This is required as Windows platform doesn't support IPIP and only BGP or VXLAN networking backend. By default Calico networking is configured with IPIP, and therefore it needs to be changed to either BGP or VXLAN when using Windows workers.

Download and configure Calico custom resources

>The `sed` command below works only with `GNU sed`. If you don't have or use non-GNU `sed`, manually edit `custom-resources.yaml` file.

>The `cidr` block should match what was selected when the cluster was initialized. Default is `192.168.0.0l/16`.

```bash
# Example to set networking backend to VXLAN
# download custom-resources.yaml
curl -O https://docs.tigera.io/manifests/custom-resources.yaml
# add networking backend configuration
sed -i '/^\s*# registry:.*$/a \
  calicoNetwork:\
    ipPools:\
    - cidr: \"192.168.0.0\/16\"\
      encapsulation: \"VXLAN\"\
      nodeSelector: all()\
      natOutgoing: \"Enabled\"' custom-resources.yaml
# deploy custom resources
kubectl apply -f custom-resources.yaml
```

Once `apiserver` component becomes available, deploy Calico Enterprise license

```bash
# watch Calico components
watch kubectl get tigerastatus

# deploy license
kubectl apply -f setup/license.yaml
```

Verify that default IPPool resource is configured with VXLAN networking backend, i.e. `vxlanMode: Always`

```bash
kubectl get ippool default-ipv4-ippool -oyaml
```

Once Calico is installed, configure strict affinity for Calico IPAM and disable BGP if you use VXLAN backend. You can configure IPAM strict affinity setting using [calicoctl](https://docs.tigera.io/maintenance/clis/calicoctl/) CLI.

You can either follow the official [calicoctl](https://docs.tigera.io/maintenance/clis/calicoctl/) guide to download and configure it, or use the helper script on the master node

```bash
# install calicoctl on master node
chmod +x setup/1-install-calicoctl.sh
./setup/1-install-calicoctl.sh
# verify
calicoctl version
```

Configure Calico IPAM strict affinity as Windows does not support IP borrowing feature and therefore Calico IPAM needs to be configured to use `strictaffinity=true`.

```bash
# view Calico IPAM configuraiton
calicoctl ipam show --show-configuration
# set strictAffinity setting
calicoctl ipam configure --strictaffinity=true
```

If you chose to use VXLAN networking backend, then disable BGP

```bash
kubectl patch installation default --type=merge -p '{"spec": {"calicoNetwork": {"bgp": "Disabled"}}}'
```

## join Windows workers

To join a Windows worker to the cluster, you need to do a few steps to prepare the node:

- copy `kubeconfig` from master node to `c:\k\config` path on Windows worker
- upload Tigera Calico for Windows zip file to `c:\tigera-calico-windows.zip` path
- execute `c:\install-calico-windows.ps1` script to configure Calico
- configure and launch `kubelet` and `kube-proxy` services

RDP into the Windows host using public IP and the `administrator` user password from the output of `terraform apply` command.
Verify that in user home directory there is `private_key.pem` file.

From your local shell upload Calico for Windows zip file to the Windows node.

>You can get the Calico Enterprise for Windows zip file from a Tigera team representative.

```bash
# upload zip over SSH from your local shell
# if prompted for password, provide administrator user password from terraform output
ZIP_PATH="/path/to/tigera-calico-windows.zip"
WIN_PUB_IP="xx.xx.xx.xx"
scp -i private_key.pem $ZIP_PATH administrator@$WIN_PUB_IP:c:/tigera-calico-windows.zip
```

Pre-pull IIS container image as it may take several minutes to pull it

```powershell
docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore
```

On the Windows node use the `private_key.pem` file to download `kubeconfig` from the master node and move it to `c:\k\config` path.

```powershell
# run these commands in Powershell on Windows node
$MASTER_IP='xx.xx.xx.xx'
# download kubeconfig file
scp -o StrictHostKeyChecking=no -i private_key.pem ubuntu@$MASTER_IP`:~/.kube/config c:\k\config
```

Save default AWS metadata routes before installing Calico

```powershell
$MetadataRoutes = Get-NetRoute -DestinationPrefix 169.254.169.*
```

Install Calico on each Windows node that you're joining to the cluster

>The `ServiceCidr` and `DNSServierIPs` parameters must match your cluster's configuration service CIDR and DNS server service IP if you build your cluster with a different service CIDR than what's used in this guide.

```powershell
# confirm kube DNS service IP
kubectl -n kube-system get svc

# use c:\install-calico-windows.ps1 quickstart script to install Calico for Windows
c:\install-calico-windows.ps1 -KubeVersion 1.20.0 -ServiceCidr '10.96.0.0/12' -DNSServerIPs 10.96.0.10
```

Configure and launch `kubelet` and `kube-proxy` services

```powershell
cd c:\TigeraCalico
# install services
.\kubernetes\install-kube-services.ps1
# start services
foreach ($svc in (Get-Service kubelet,kube-proxy)){
  if ($svc.Status -notmatch 'Running'){
    Start-Service $svc.Name
  }
}
```

When Calico gets installed on a Windows host, the default AWS metadata routes can go missing from the host. Check for AWS default metadata routes and add them back if they're missing.

```powershell
# check if route is in place
Get-NetRoute -DestinationPrefix 169.254.169.*
# if routes are missing, use $MetadataRoutes variable set in one of the previous steps
$PvtIpIfaceIndex = (Get-NetRoute -DestinationPrefix 172.16.0.* | select -First 1).InterfaceIndex
foreach ($route in $MetadataRoutes){
  if (-not(Get-NetRoute -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue)){
    echo "addin route $($route.DestinationPrefix) with interface $PvtIpIfaceIndex"
    New-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $PvtIpIfaceIndex
  }
}
```

Verify that Windows workers were added to the cluster

```bash
# run from master node or local shell (if configured)
# get cluster Windows workers only
kubectl get node -l "beta.kubernetes.io/os=windows"
```

[Continue with deploying applications and testing connectivity](../../README.md#deploy-apps-and-test-connectivity).
