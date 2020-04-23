# Getting up and running with Calico for Windows

In this guide words `node` and `host` are interchangeable.

## High level tasks to install Calico for Windows

- provision two Ubuntu instances: one for k8s master, and one for k8s worker
- provision one or two Windows instances. For example, `Windows 1903` and `Windows 1909` with Containers feature installed
- prepare Ubuntu instances for k8s installation
- use `kubeadm` to install k8s Ubuntu instances
- [install Calico](https://docs.projectcalico.org/getting-started/kubernetes/quickstart) OS v3.13.x
- prepare Windows nodes to be joined to k8s cluster
- use `Calico for Windows` v3.12.1 to install Calico on Windows nodes and join the nodes to k8s cluster
- test connectivity between Linux and Windows pods

## provision cluster infrastructure

```bash
git clone https://github.com/tigera-solutions/install-calico-for-windows.git
cd install-calico-for-windows/cluster
chmod +x provision-cluster.sh
./provision-cluster.sh
```

## launch k8s cluster and join Linux workers

`SSH` into master node and launch k8s control plane. The `cluster/cloud-config.yaml` contains example configuration for k8s cluster and can be used to launch the cluster.

```bash
MASTER0_IP='xx.xx.xx.xx' # set master node public IP
WORKER1_IP='xx.xx.xx.xx' # set linux worker node public IP
SSH_KEY='./path/to/ssh_key'
ssh -i $SSH_KEY -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$MASTER0_IP
# copy kubeadm example config
sudo cp /root/kubeadm/kubeadm-config.yaml ./
# export k8s control plane endpoint var
export MASTER_PUB_IP=$MASTER0_IP
sed -i -- 's/\#controlPlaneEndpoint:\ $MASTER_PUB_IP/controlPlaneEndpoint: $MASTER_PUB_IP/g' ./kubeadm-config.yaml
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
MASTER0_IP='xx.xx.xx.xx' # set master node public IP
WORKER1_IP='xx.xx.xx.xx' # set linux worker node public IP
SSH_KEY='./path/to/ssh_key'
ssh -i $SSH_KEY -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@$WORKER1_IP
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
## - replace CALICO_IPV4POOL_IPIP var with CALICO_IPV4POOL_VXLAN var
## - replace calico_backend: "bird" with calico_backend: "vxlan"
## - comment out the line - -bird-ready and - -bird-live from the calico/node readiness/liveness check
# install Calico
kubectl apply -f calico.yaml
```

Retrieve `kube-proxy` DaemonSet and `coredns` Deployment and make sure each has `nodeSelector` configured to run on Linux only.
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

## configure Windows workers

Copy Tigera Calico for Windows installation package to each Windows node. Use RDP session to login onto Windows node to setup Windows worker.

```bash
# retrieve Windows instance password for RDP session
SSH_KEY='./path/to/ssh_key'
WIN_INST_ID='i-xxxx' # set Windows node Id
aws ec2 get-password-data --instance-id $WIN_INST_ID --priv-launch-key $SSH_KEY --query 'PasswordData' --output text
```

Open `kubelet` port in the firewall and enable required Windows features

```powershell
# open kubelet port
netsh advfirewall firewall add rule name="Kubelet port 10250" dir=in action=allow protocol=TCP localport=10250
# enable `RemoteAccess` feature on each Windows node
# view if feature already installed
Get-WindowsFeature -Name RemoteAccess
# install the feature
Install-WindowsFeature -Name RemoteAccess
# check WinDSR feature
Get-WindowsFeature -Name Routing
Install-WindowsFeature -Name Routing
# have to restart instance to apply changes
Restart-Computer
# once rebooted
Install-RemoteAccess -VpnType RoutingOnly
# if not running, start the service
Get-Service RemoteAccess
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
# get kube v1.18.2 binaries
$KubernetesVersion='v1.18.2'
# download archived version that contains all node binaries
iwr -usebasicparsing -outfile kubernetes-node-windows-amd64.tar.gz -uri https://dl.k8s.io/v1.18.2/kubernetes-node-windows-amd64.tar.gz
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

### configure `kubelet` components

These settings must be configured in kubelet's configuration:

- `--network-plugin=cni`
- `--cni-bin-dir=​<directoryforCNIbinaries>`
- `--cni-conf-dir=​<directoryforCNIconfiguration>`
- `--hostname-override` - on AWS instance must be set to instance's internal DNS (e.g. `ip-10-0-0-21.us-west-2.compute.internal`)
- `--node-ip` - should be explicitly set to host's main network adapter's IP (e.g. `10.0.0.21`)
- `--max-pods` ​should be set to, at most, the IPAM block size of the IP pool in use minus 4 (i.e. `2^(32-n) - 4`)

Note, each node in the cluster must have `KubernetesCluster` tag defined. The `./provision-cluster.sh` script sets this tag for each node.
Calico files already provide a helper `C:\TigeraCalico\kubernetes\start-kubelet.ps1` script to start the `kubelet`. Open the file and adjust necessary parameters before launching the script.
For more details refer to `C:\TigeraCalico\kubernetes\README.txt` file.

```powershell
# adjust parameters
notepad.exe C:\TigeraCalico\kubernetes\start-kubelet.ps1
```

### configure `kube-proxy` component

The `kube-proxy` reads the `HNS` network name from an environment variable `K​UBE_NETWORK`.
With default configuration Calico uses network name `Calico` and flannel uses network name `cbr0`.

## install Calico on Windows nodes

Edit the file `​C:\TigeraCalico\config.ps1​` as follows:

- Set `$env:KUBE_NETWORK​` to match the CNI plugin you plan to use. For Calico, set the variable to `"Calico.*"`, for flannel host gateway it is typically `"cbr0"`.
- Set `$env:CALICO_NETWORKING_BACKEND​` to `"windows-bgp"`, `"vxlan"`, or `"none"` (if using a non-Calico CNI plugin).
- Set the ​`$env:CNI_` ​variables to match the location of your `Kubernetes` installation.
- Set `$env:K8S_SERVICE_CIDR​` to match your `Kubernetes` service cluster IP CIDR.
- Set `$env:CALICO_DATASTORE_TYPE​` to the Calico datastore you want to use. Note: `"etcdv3"` can only be used with Calico BGP networking. When using flannel or another networking provider, the `Kubernetes` API Datastore must be used.
- Set `$env:KUBECONFIG​` to the location of the `kubeconfig` file Calico should use to access the `Kubernetes` API server.
- If using `etcd` as the datastore, set the `$env:ETCD_​` parameters accordingly. ​Note: due to a limitation of the Windows dataplane, a `Kubernetes` service `ClusterIP` cannot be used for the `etcd` endpoint (the host compartment cannot reach `Kubernetes` services).
- Set `$env:NODENAME​` to match the hostname used by `kubelet`. The default is to use the node's hostname.

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

## deploy apps and test connectivity

```bash
# deploy nginx stack to Linux host
kubectl apply -f app/stack-nginx.yml
# deploy iis stack to Windows host
kubectl apply -f app/stack-iis.yml
# deploy utility pod
kubectl apply -f app/netshoot.yml
# connect to utility pod and test connectivity
kubectl exec -it netshoot -- bash
# resolve dns
nslookup nginx-svc
nslookup iis-svc
# curl apps
curl -Is http://nginx-svc | grep -i http
curl -Is http://iis-svc | grep -i http
exit
# connecto to iis pod and test connectivity to nginx pod
IIS_POD=$(kubectl get pod -l run=iis -o jsonpath='{.items[*].metadata.name}')
kubectl exec -it $IIS_POD -- powershell
# resolve DNS and test connectivity
Resolve-DnsName -Name nginx-svc
iwr -UseBasicParsing http://nginx-svc
```
