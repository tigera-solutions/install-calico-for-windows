# Provision k8s environment in Azure

These instructions provide configuration example of a k8s cluster using Azure infrastructure.

## using scripted configuration

The fasted way to provision and configure the unmanaged Kubernetes (k8s) cluster is to use scripts in this repository. The main script `provision-cluster.sh` provisions Azure VM instances ready for k8s installation. The script outputs several resources in the end:

- `helper-upload-assets-to-master.sh` - used to upload assets to the linux master node. The Calico for Windows `ZIP` is assumed to be at the `/tmp` dir (e.g. `/tmp/tigera-calico-windows-v3.12.1.zip`).
- `helper-prep-master-node.sh` - should be used on a `master` host to prepare k8s `master` node and download k8s binaries for Windows.
  >This was done to speed up Windows configuration process as direct download of k8s binaries to a Windows node was taking significantly more time.
- `helper-prep-win-node.ps1` - configures necessary features and a service on Windows host. Must be executed on a Windows node in `Powershell`.
- `helper-configure-calico.ps1` - configures and installs Calico and k8s components. Must be executed on a Windows node in `Powershell`.

Follow instructions in the next three sections to install and configure k8s cluster. Make sure to install Calico CNI before moving onto configuring Windows hosts. Once CNI is installed, the scripted approach can be used to configure Windows hosts. The flow for scripted installation is the following:

- upload `Calico for Windows` package (e.g. `tigera-calico-windows-v3.12.1.zip`) into the `$HOME` of `azureuser` user on the `master` host. You can use `helper-upload-assets-to-master.sh` script to upload necessary assets to the `master` host.

  ```bash
  SSH_KEY='/path/to/ssh_key'
  CALICO_ZIP='/path/to/calico_zip'
  chmod +x helper-upload-assets-to-master.sh
  ./helper-upload-assets-to-master.sh $SSH_KEY $CALICO_ZIP
  ```

- copy `helper-prep-master-node.sh` script into `$HOME` directory of `azureuser` user on the `master` host and execute it.

  ```bash
  # SSH into master node and run the script
  chmod +x helper-prep-master-node.sh
  ./helper-prep-master-node.sh
  ```

- copy private SSH key into `$HOME` directory on Windows host. Make sure to use the matching private key pair for the public key you provided to `provision-cluster.sh` script.

  ```bash
  # RDP into Windows host and download necessary assets
  SSH_KEY="$HOME\ssh_key"
  MASTER0_IP='xx.xx.xx.xx'
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/tigera-calico-windows-v3.12.1.zip .\Downloads\
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/helper-prep-win-node.ps1 .\Downloads\
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/helper-configure-calico.ps1 .\Downloads\
  ```

- copy `helper-prep-win-node.ps1` script into `$HOME\Downloads` path and execute it.
  >This will reboot the instance. If prompted, confirm the reboot action.
- copy `helper-configure-calico.ps1` script into `$HOME\Downloads` path and execute it.

  ```bash
  SSH_KEY="$HOME\ssh_key"
  cd .\Downloads\
  # prepare Windows node
  .\helper-prep-win-node.ps1
  # configure Kubernetes components and install Calico
  .\helper-configure-calico.ps1 -SshKeyPath $SSH_KEY
  ```

## using manual provisioning of cluster infrastructure

Since the required version of Windows could be different for users, you can retrieve the desired `sku` using Azure CLI commands. Use `arm/parameters.json` file to set `windowsImageSKU` parameter.

```bash
# get all SKUs for 2019 Windows images
az vm image list -l westus2 -p MicrosoftWindowsServer -f WindowsServer --all --output table | grep -i '2019\-'
```

Clone the Github repo, set required parameters and execute the script to provision the infrastructure.

```bash
# clone repo
git clone https://github.com/tigera-solutions/install-calico-for-windows.git
cd install-calico-for-windows/cluster/azure
chmod +x provision-cluster.sh
# set vars
SSH_KEY_PATH='/path/to/ssh_pub_key'
RESOURCE_GROUP='calico'
LOCATION='westus2'
PROJECT_NAME='c4w'
SSH_PUB_KEY="$(cat $SSH_KEY_PATH)"
# provision infrastructure
./provision-cluster.sh $RESOURCE_GROUP $LOCATION $PROJECT_NAME $SSH_PUB_KEY
```

### launch k8s cluster and join Linux workers

`SSH` into the master node and initialize k8s control plane. The `cluster/cloud-config.yaml` contains example configuration for k8s cluster and can be used to launch the cluster.

```bash
MASTER0_IP='xx.xx.xx.xx' # set master node public IP in your local shell
SSH_KEY='./path/to/ssh_key'
cmhod 0600 $SSH_KEY
ssh -i $SSH_KEY -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no azureuser@$MASTER0_IP
# commands below should be executed from the master node
MASTER0_IP=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text") # get master node public IP from VM metadata
# copy kubeadm example config
sudo cp /root/kubeadm/kubeadm-config.yaml ./
sudo chown azureuser:azureuser ./kubeadm-config.yaml
# export k8s control plane endpoint var
export MASTER_PUB_IP=$MASTER0_IP
# sed -i "" 's/\#controlPlaneEndpoint:\ $MASTER_PUB_IP/controlPlaneEndpoint: $MASTER_PUB_IP/g' ./kubeadm-config.yaml
envsubst < kubeadm-config.yaml > cluster-config.yaml
# launch k8s cluster
sudo kubeadm init --config=cluster-config.yaml
# get certificate hash and join token to use with join command
CERT_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')
JOIN_TOKEN=$(kubeadm token list -o jsonpath='{.token}')
```

Once control plane is launched execute suggested commands from `kubeadm init` output.

```bash
# run suggested kubeadm commands
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
# list cluster nodes
kubectl get nodes
```

 Use `kubeadm join` command (i.e. without `--control-plane`) to join any Linux worker nodes to the cluster.

```bash
WORKER1_IP='xx.xx.xx.xx' # set linux worker node public IP
SSH_KEY='./path/to/ssh_key'
ssh -i $SSH_KEY -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no azureuser@$WORKER1_IP
# commands below should be executed on each worker node
MASTER0_IP='xx.xx.xx.xx' # set master node public IP
# join Linux worker node
JOIN_TOKEN='xxxxx'
CERT_HASH='xxxxx' # use certificate hash value retrieved from master node
sudo kubeadm join ${MASTER0_IP}:6443 --token $JOIN_TOKEN --discovery-token-ca-cert-hash sha256:${CERT_HASH}
```

[Continue with Calico installation](../../README.md#install-and-configure-calico).

## troubleshooting ARM template deployment errors

```bash
# if deployment fails, use `Correlation ID` in the printed error to get more details about the error
az monitor activity-log list --correlation-id 25296ac4-0d8b-4eb9-9aca-5ac82d86804a --query '[].properties.statusMessage'

# view deployed VM extensions
VM_NAME="$PROJECT_NAME-vm-win0"
az vm extension list -g $RESOURCE_GROUP --vm-name $VM_NAME
```

## cleanup provisioned resources

When cluster is no longer needed you can cleanup provisioned resources using `arm/cleanup.json` or simply deleting the resource group that holds all cluster resources.

```bash
# remove all resources in the resource group but do not delete the resource group itself
az deployment group create --resource-group $RESOURCE_GROUP --template-file arm/cleanup.json --mode Complete

# delete the resource group with all its resources
az group delete -n $RESOURCE_GROUP --yes --output jsonc
```
