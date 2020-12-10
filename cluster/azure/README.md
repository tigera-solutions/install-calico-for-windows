# Provision k8s environment in Azure

These instructions provide configuration example of a k8s cluster using Azure infrastructure.

## provision cluster infrastructure

A quick way to provision and configure the unmanaged Kubernetes (k8s) cluster is to use scripts in this repository. The main script `provision-cluster.sh` provisions Azure VM instances ready for k8s installation.

Since the required version of Windows could differ for users, you can retrieve the desired `sku` using Azure CLI commands. Use `arm/parameters.json` file to set `windowsImageSKU` parameter.

```bash
# get all SKUs for Windows 1909 images
az vm image list -l westus2 -p MicrosoftWindowsServer -f WindowsServer --all --output table | grep '1909-'

# a few SKUs to use
# 2019-Datacenter-Core-with-Containers
# Datacenter-Core-1903-with-Containers-smalldisk
# datacenter-core-1909-with-containers-smalldisk
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
KUBE_VERSION="1.18.8"
# provision infrastructure
./provision-cluster.sh $RESOURCE_GROUP $LOCATION $PROJECT_NAME $SSH_PUB_KEY $KUBE_VERSION
```

## OPTION 1: using scripted configuration

The `provision-cluster.sh` script creates several resources:

- `helper-upload-assets-to-master.sh` - used to upload assets to the linux master node. The Calico for Windows `ZIP` is assumed to be at the `/tmp` dir (e.g. `/tmp/tigera-calico-windows-v3.12.1.zip`).
- `helper-prep-master-node.sh` - should be used on a `master` host to prepare k8s `master` node and download k8s binaries for Windows.
  >This was done to speed up Windows configuration process as direct download of k8s binaries to a Windows node was taking significantly more time.
- `helper-prep-win-node.ps1` - configures necessary features and a service on Windows host. Must be executed on a Windows node in `Powershell`.
  >This script is provided as a reference to configure necessary Windows features. It is executed as a part of Windows VM provisioning process.

- `helper-configure-calico.ps1` - configures and installs Calico and k8s components. Must be executed on a Windows node in `Powershell`.

These instructions guide through a scripted configuration of k8s cluster. Make sure to [install `Calico CNI`](../../README.md#install-and-configure-calico) before moving onto configuring Windows hosts. Once CNI is installed, the scripted approach can be used to configure Windows hosts. The flow for scripted installation is the following:

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

  >The script will output the `kubeadm init` command that can be used to initialize k8s cluster. Once the master node is initialized, join remaining Linux worker node(s). Then [install `Calico CNI`](../../README.md#install-and-configure-calico) before moving onto the next step to configure Windows hosts.

- copy private SSH key into `$HOME` directory on Windows host. Make sure to use the matching private key pair for the public key you provided to `provision-cluster.sh` script.

  ```bash
  # RDP into Windows host and download necessary assets
  if ([string]::IsNullOrEmpty($SSH_KEY)){
    Write-Warning "SSH key is not set"
    $SSH_KEY = Read-Host "provide SSH key path"
  }
  if ([string]::IsNullOrEmpty($MASTER0_IP)){
    Write-Warning "Master node IP is not set"
    $MASTER0_IP = Read-Host "provide master node IP that hosts required assets (i.e. scripts, k8s Windows bits)"
  }
  echo "using SSH key: $SSK_KEY"
  echo "using master node with IP: $MASTER0_IP"
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/tigera-calico-windows-v3.12.1.zip .\Downloads\
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/helper-prep-win-node.ps1 .\Downloads\
  scp.exe -o StrictHostKeyChecking=no -i $SSH_KEY azureuser@$MASTER0_IP`:~/helper-configure-calico.ps1 .\Downloads\
  ```

- copy `helper-prep-win-node.ps1` script into `$HOME\Downloads` path and execute it.
  >This script is provided as a reference how to configure necessary Windows features. It is executed as a part of Windows VM provisioning process.
  >Check whether features were installed `Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN; Get-Service RemoteAccess`, and if so, move onto the next step. Otherwise run it to install necessary features. The script will force reboot the instance.
- copy `helper-configure-calico.ps1` script into `$HOME\Downloads` path and execute it.

  ```bash
  # exec these code block on Powershell on Windows host(s)
  if ([string]::IsNullOrEmpty($SSH_KEY)){
    Write-Warning "SSH key is not set"
    $SSH_KEY = Read-Host "provide SSH key path"
  }
  cd .\Downloads\
  # prepare Windows node
  # check if required featured already installed
  if (((Get-WindowsFeature RemoteAccess).InstallState -notlike 'installed') -or ((Get-WindowsFeature Routing).InstallState -notlike 'installed') -or ((Get-WindowsFeature DirectAccess-VPN).InstallState -notlike 'installed')) {
    .\helper-prep-win-node.ps1
  }
  # configure Kubernetes components and install Calico
  echo "using SSH key: $SSK_KEY"
  .\helper-configure-calico.ps1 -SshKeyPath $SSH_KEY
  ```

- create a temporary `POD` to finalize network configuration on Windows host

  ```bash
  c:\k\kubectl --kubeconfig=c:\k\config run nano --rm -it --image mcr.microsoft.com/windows/nanoserver:latest --image-pull-policy=IfNotPresent --restart=Never --command cmd /c 'echo hello'
  ```

[Deploy test apps](../../README.md#deploy-apps-and-test-connectivity) and test connectivity.

## OPTION 2: using manual provisioning of cluster infrastructure

Before continuing with manual k8s cluster configuration, make sure to [provision necessary infrastructure](#provision-cluster-infrastructure) for the cluster.

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

## install and configure Calico

Before Windows nodes can be joined to the cluster, Calico CNI should be installed on Linux part of the cluster. The easiest way to install Calico is to follow [quickstart installation guide](https://docs.projectcalico.org/getting-started/kubernetes/quickstart).
If using Calico VXLAN networking, [customize](https://docs.projectcalico.org/getting-started/kubernetes/installation/config-options) `calico.yaml` manifest before deploying Calico.

```bash
# download calico manifest
curl -O https://docs.projectcalico.org/manifests/calico.yaml
# if using BGP networking, set CALICO_IPV4POOL_IPIP to "Never" and then apply the manifest
# if using VXLAN networking:
## - make sure CALICO_IPV4POOL_IPIP var is set to "Never" and CALICO_IPV4POOL_VXLAN var is set to "Always"
sed -i "" '/CALICO_IPV4POOL_VXLAN/{N;d;}' ./calico.yaml
sed -i "" 's/CALICO_IPV4POOL_IPIP/CALICO_IPV4POOL_VXLAN/1' ./calico.yaml
## - replace calico_backend: "bird" with calico_backend: "vxlan"
sed -i "" 's/calico_backend: "bird"/calico_backend: "vxlan"/1' ./calico.yaml
## - comment out the line - -bird-live and - -bird-ready from the calico/node liveness/readiness check
sed -i "" '/- -bird-live/d' ./calico.yaml
sed -i "" '/- -bird-ready/d' ./calico.yaml
# install Calico
kubectl apply -f calico.yaml
```

>`sed` command format could be different on your workstation. Adjust accordingly if needed.

Retrieve `kube-proxy` DaemonSet and `coredns` Deployment and make sure each has `nodeSelector` configured to run on Linux node only.
For instance:

```yaml
nodeSelector:
  kubernetes.io/os: linux
```

or

```yaml
nodeSelector:
  beta.kubernetes.io/os: linux
```

Redeploy `kube-proxy` and `coredns` if necessary.

Enable `strictaffinity` for Calico networking since Windows networking does not support IP borrowing feature. The [calicoctl](https://docs.projectcalico.org/getting-started/clis/calicoctl/install) has to be used to tweak the setting.

```bash
# set StrictAffinity configuration setting
calicoctl ipam configure --strictaffinity=true

# verify the IPAM configuration
calicoctl ipam show --show-configuration
```

## configure Windows workers

Copy Tigera Calico for Windows installation package to each Windows node. Use RDP session to login onto Windows node to setup Windows worker.

```bash
# retrieve Windows instance password for RDP session in AWS
SSH_KEY='./path/to/ssh_key'
WIN_INST_ID='i-xxxx' # set Windows node Id
aws ec2 get-password-data --instance-id $WIN_INST_ID --priv-launch-key $SSH_KEY --query 'PasswordData' --output text
```

Open `kubelet` port in the firewall and enable required Windows features

>Calico CNI requires `RemoteAccess, Routing, DirectAccess-VPN` Windows features to be installed on the host.

```powershell
# open kubelet port
netsh advfirewall firewall add rule name="Kubelet port 10250" dir=in action=allow protocol=TCP localport=10250
# enable `RemoteAccess` feature on each Windows node
# view if features already installed
Get-WindowsFeature -Name RemoteAccess,Routing,DirectAccess-VPN
# install the features
Install-WindowsFeature -Name RemoteAccess,Routing
# verify that these features were installed
Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN
# if DirectAccess-VPN feature wasn't installed, then explicitly install it
Install-WindowsFeature -Name DirectAccess-VPN
# check if the service is enabled after it was installed. If not, enable the service
# make sure RemoteAccess service is not disabled
Get-Service RemoteAccess | select -Property name,status,starttype
# or get service using WMI object
Get-WMIObject win32_service | ?{$_.Name -like 'remoteaccess'}
# if disabled set the startmode to Automatic
Set-Service -Name RemoteAccess -ComputerName . -StartupType "Automatic"
# have to restart instance to apply changes
Restart-Computer
# once rebooted
Get-Service RemoteAccess
# if not running, start the service
Start-Service RemoteAccess
```

Extract Calico files

```powershell
# extract Calico files
Expand-Archive $HOME\Downloads\tigera-calico-windows-v3.12.1.zip c:\
```

Pre-load Windows docker images onto each host

```powershell
$WIN_CORE_VER=$((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId)
docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-$WIN_CORE_VER
docker pull mcr.microsoft.com/windows/nanoserver:$WIN_CORE_VER
docker pull mcr.microsoft.com/windows/nanoserver:${WIN_CORE_VER}-amd64
# tag nanoserver as latest
docker tag mcr.microsoft.com/windows/nanoserver:${WIN_CORE_VER}-amd64 mcr.microsoft.com/windows/nanoserver:latest
docker tag mcr.microsoft.com/windows/servercore/iis:windowsservercore-$WIN_CORE_VER mcr.microsoft.com/windows/servercore/iis:windowsservercore
```

Build kubernetes `pause` image on each Windows host

```powershell
# download Dockerfile
cd $HOME\Documents
mkdir pause; cd pause
iwr -usebasicparsing -outfile Dockerfile -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile
# build pause image
docker build -t kubeletwin/pause .
```

Configure `kubernetes` on each Windows host. Choose [`kubernetes` version](https://github.com/kubernetes/kubernetes/tree/master/CHANGELOG) and download client and node binaries.

```powershell
# create kube folders
mkdir c:\k
mkdir c:\k\cni
mkdir c:\k\cni\config
# download kube components from kubernetes
cd $HOME\Downloads
# get kube v1.18.5 binaries
$KubernetesVersion='v1.18.5'
# download archived version that contains all node binaries
iwr -usebasicparsing -outfile kubernetes-node-windows-amd64.tar.gz -uri https://dl.k8s.io/$KubernetesVersion/kubernetes-node-windows-amd64.tar.gz
# extract kube components
tar.exe -xf kubernetes-node-windows-amd64.tar.gz
# or download node binaries one by one
iwr -usebasicparsing -outfile kubelet.exe -uri https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubelet.exe
iwr -usebasicparsing -outfile kube-proxy.exe -uri https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kube-proxy.exe
iwr -usebasicparsing -outfile kubectl.exe -uri https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubectl.exe
iwr -usebasicparsing -outfile kubeadm.exe -uri https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubeadm.exe
# copy kube components to c:\k path
cp .\kubernetes\node\bin\*.exe c:\k
# get kubeconfig from the master node and copy it into c:\k\config path
# NOTE: make sure to save .\config file without any extension
notepad.exe c:\k\config
# remove txt extension
mv C:\k\config.txt C:\k\config
# set KUBECONFIG env var and test cluster connection
$env:KUBECONFIG="c:\k\config"
cd c:\k
Set-Alias -Name kubectl -Value "c:\k\kubectl.exe"
kubectl version
kubectl get nodes
# download CNI plugins
$CNI_DIR='c:\k\cni'
iwr -usebasicparsing -outfile $CNI_DIR\flannel.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe
iwr -usebasicparsing -outfile $CNI_DIR\win-bridge.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe
iwr -usebasicparsing -outfile $CNI_DIR\host-local.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe
```

## configure and install Calico on Windows nodes

There are main steps to install Calico on Windows host:

- configure and install Calico using `C:\TigeraCalico\config.ps1` helper script
- launch `kubelet` process via `C:\TigeraCalico\kubernetes\start-kubelet.ps1` helper script
- launch `kube-proxy` process via `C:\TigeraCalico\kubernetes\start-kube-proxy.ps1` helper script

>Once you start `C:\TigeraCalico\config.ps1` script, it is expected that the host may lose connectivity for a brief moment. Windows networking is sensitive to the changes the script makes. The connection usually is restored within a few seconds.

>The `kube-proxy` process may appear to be stuck while rendering the message `Waiting for HNS network Calico to be created...`. The script waits for a POD to come up on the Windows host in order to proceed with `kube-proxy` configuration. You can speed up this process by creating a container directly on the host, e.g. `c:\k\kubectl --kubeconfig=c:\k\config run nano --rm -it --image mcr.microsoft.com/windows/nanoserver:latest --image-pull-policy=IfNotPresent --restart=Never --command cmd /c 'echo hello'`.
When configuring multiple Windows hosts, you can use `nodeSelector` in order to pin a POD to a specific when configuring `kube-proxy` on the host.

### configure Calico installation components

Edit the file `​C:\TigeraCalico\config.ps1​` as follows:

- Set `$env:KUBE_NETWORK​` to match the CNI plugin you plan to use. For Calico, set the variable to `"Calico.*"`, for flannel host gateway it is typically `"cbr0"`.
- Set `$env:CALICO_NETWORKING_BACKEND​` to `"windows-bgp"`, `"vxlan"`, or `"none"` (if using a non-Calico CNI plugin).
- Set the ​`$env:CNI_` ​variables to match the location of your `Kubernetes` installation.
- Set `$env:K8S_SERVICE_CIDR​` to match your `Kubernetes` service cluster IP CIDR.
- Set `$env:CALICO_DATASTORE_TYPE​` to the Calico datastore you want to use. Note: `"etcdv3"` can only be used with Calico BGP networking. When using flannel or another networking provider, the `Kubernetes` API Datastore must be used.
- Set `$env:KUBECONFIG​` to the location of the `kubeconfig` file Calico should use to access the `Kubernetes` API server.
- If using `etcd` as the datastore, set the `$env:ETCD_​` parameters accordingly. ​Note: due to a limitation of the Windows dataplane, a `Kubernetes` service `ClusterIP` cannot be used for the `etcd` endpoint (the host compartment cannot reach `Kubernetes` services).
- **Must** set `$env:NODENAME​` to **match** the hostname used by `kubelet`. The default is to use the node's hostname.

example configuration for `.\config.ps1`

```powershell
# open file and adjust parameters
notepad.exe C:\TigeraCalico\config.ps1
# assuming node name (in AWS internal DNS) is 'ip-10-0-0-21.us-west-2.compute.internal'
# no need to change NODENAME var on Azure
$env:NODENAME = "ip-10-0-0-21.us-west-2.compute.internal"
# when using VXLAN, set it to "vxlan"
$env:CALICO_NETWORKING_BACKEND="vxlan"
# set datastore type
$env:CALICO_DATASTORE_TYPE = "kubernetes"
# if IP autodetection can't select the correct IP, set it manually. You can view which IP Calico selected in the C:\TigeraCalico\logs\tigera-node.log
# $env:IP = "autodetect"
````

### configure `kubelet` components

These settings must be configured in kubelet's configuration:

- `--network-plugin=cni`
- `--cni-bin-dir=​<directoryforCNIbinaries>`
- `--cni-conf-dir=​<directoryforCNIconfiguration>`
- `--hostname-override` - on AWS instance must be set to instance's internal DNS (e.g. `ip-10-0-0-21.us-west-2.compute.internal`)
- `--node-ip` - should be explicitly set to host's main network adapter's IP (e.g. `10.0.0.21`)
- `--max-pods` ​should be set to, at most, the IPAM block size of the IP pool in use minus 4 (i.e. `2^(32-n) - 4`)

>Note, each node in AWS cluster should have `KubernetesCluster` and `kubernetes.io/cluster` tags defined. The `./cluster/aws/provision-cluster.sh` script sets this tag for each node.

Calico files already provide a helper `C:\TigeraCalico\kubernetes\start-kubelet.ps1` script to start the `kubelet`. Open the file and adjust necessary parameters before launching the script.
For more details refer to `C:\TigeraCalico\kubernetes\README.txt` file.

```powershell
# open file and adjust parameters
notepad.exe C:\TigeraCalico\kubernetes\start-kubelet.ps1
```

example configuration

>Note: there is no need to explicitly configure `--hostname-override` flag if `$env:NODENAME` env var is set in `C:\TigeraCalico\config.ps1`.

```powershell
# find '--hostname-override=' and set to correct host name (on AWS it should be set to node's internal DNS, e.g. 'ip-10-0-0-21.us-west-2.compute.internal')
# find '--node-ip=' and set to host's main IP (e.g. '10.0.0.21')
# in most cases you can leave $NodeIp blank to let the script auto-detect host's IP address
$NodeIp = "10.0.0.21"
$NodeName = "ip-10-0-0-21.us-west-2.compute.internal"
$argList = @(`
    "--hostname-override=$NodeName", `
    "--node-ip=$NodeIp", `
    .....
)
```

### configure `kube-proxy` component

The `kube-proxy` reads the `HNS` network name from an environment variable `K​UBE_NETWORK`.
With default configuration Calico uses network name `Calico` and flannel uses network name `cbr0`.

example configuration

>Note: there is no need to explicitly configure `--hostname-override` flag if `$env:NODENAME` env var is set in `C:\TigeraCalico\config.ps1`.

```powershell
# open file and adjust parameters
notepad.exe C:\TigeraCalico\kubernetes\start-kube-proxy.ps1

# find '--hostname-override=' and set to correct host name (on AWS it should be set to node's internal DNS, e.g. 'ip-10-0-0-21.us-west-2.compute.internal')
$NodeName = "ip-10-0-0-21.us-west-2.compute.internal"
$argList = @(`
    "--hostname-override=$NodeName", `
    .....
)
```

Start `kubelet`, `kube-proxy` and install `calico`

```powershell
# install Calico
cd C:\TigeraCalico\
.\install-calico.ps1
# start kubelet
cd C:\TigeraCalico\kubernetes
.\start-kubelet.ps1
# start kube-proxy
.\start-kube-proxy.ps1
# .\start-kube-proxy.ps1 script waits for a POD to be created before launching kube-proxy.exe
# you can manually create a POD to speed up the kube-proxy configuration
Set-Alias -Name kubectl -Value "c:\k\kubectl.exe"
$env:KUBECONFIG="c:\k\config"
kubectl run nano --rm -it --image mcr.microsoft.com/windows/nanoserver:latest --image-pull-policy=IfNotPresent --restart=Never --command ping localhost
```

Helper scripts

```powershell
# install Calico
cd C:\TigeraCalico\
# start or stop Calico
.\start-calico.ps1
.\stop-calico.ps1
# uninstall Calico
.\uninstall-calico.ps1
```

[Deploy test apps](../../README.md#deploy-apps-and-test-connectivity) and test connectivity.

## troubleshooting ARM template deployment errors

```bash
# if deployment fails, use `Correlation ID` in the printed error to get more details about the error
az monitor activity-log list --correlation-id 25296ac4-0d8b-4eb9-9aca-5ac82d86804a --query '[].properties.statusMessage'

# view deployed VM extensions
VM_NAME="$PROJECT_NAME-vm-win0"
az vm extension list -g $RESOURCE_GROUP --vm-name $VM_NAME

# if extension script fails on Windows, inspect extension log files on the VM
ls 'C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension'

# inspect downloaded files for the extension on Windows VM
ls 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.*\Downloads\'
```

## cleanup provisioned resources

When cluster is no longer needed you can cleanup provisioned resources using `arm/cleanup.json` or simply deleting the resource group that holds all cluster resources.

```bash
# remove all resources in the resource group but do not delete the resource group itself
az deployment group create --resource-group $RESOURCE_GROUP --template-file arm/cleanup.json --mode Complete

# delete the resource group with all its resources
az group delete -n $RESOURCE_GROUP --yes --output jsonc
```
