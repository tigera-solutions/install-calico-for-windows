# Getting up and running with Calico for Windows

In this guide words `node` and `host` are interchangeable. As of release of Calico v3.16.0 [windows support](https://docs.projectcalico.org/release-notes/#windows-support) was added to the open sourced edition of Calico and can now be used free of charge.

>While the Calico installation and configuration instructions in this guide cover the commercial version of Calico for Windows, for open sourced version of the installation guide refer to [projectcalico documentation](https://docs.projectcalico.org/getting-started/windows-calico/).

## before you begin

Make sure to use the correct Windows version with build `18317+` if you want to use network policies on Windows. For [more details](https://docs.projectcalico.org/getting-started/windows-calico/limitations#service-clusterips-incompatible-with-selectorspod-ips-in-network-policy) refer to [projectcalico documentation](https://docs.projectcalico.org/getting-started/windows-calico/).

## high level tasks to install Calico for Windows

- provision two Ubuntu instances: one for k8s master, and one for k8s worker
- provision one or two Windows instances. For example, `Windows 1903` and `Windows 1909` with Containers feature installed
- prepare Ubuntu instances for k8s installation
- use `kubeadm` to install k8s Ubuntu instances
- [install Calico](https://docs.projectcalico.org/getting-started/kubernetes/quickstart)
- prepare Windows nodes to be joined to k8s cluster
- use `Calico for Windows` v3.12.1 or newer to install Calico on Windows nodes and join the nodes to k8s cluster
- test connectivity between Linux and Windows pods
- use network policies to tighten security

## provision k8s cluster

Follow one of the following instructions to provision an unmanaged k8s cluster:

- [provision k8s cluster in AWS](cluster/aws/README.md)
- [provision k8s cluster in Azure](cluster/azure/README.md)

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
#############################################
# one-liners to test the network connectivity
#############################################
# test service DNS resolution and curl Nginx endpoint
kubectl exec -t netshoot -- sh -c 'SVC=nginx-svc; nslookup $SVC; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
# test service DNS resolution and curl IIS endpoint
kubectl exec -t netshoot -- sh -c 'SVC=iis-svc; nslookup $SVC; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
# connecto to iis pod and test connectivity to nginx pod
IIS_POD=$(kubectl get pod -l run=iis -o jsonpath='{.items[*].metadata.name}')
# kubectl exec -it $IIS_POD -- powershell
# resolve DNS and test connectivity
kubectl exec -t $IIS_POD -- powershell -command 'Resolve-DnsName -Name nginx-svc'
# NOTE: make sure to use Windows Server 1903+ to curl other kube services from Windows PODs
# test nginx pod port access
kubectl exec -t $IIS_POD -- powershell -command 'Test-NetConnection -ComputerName nginx-svc -Port 80'
# curl nginx service
kubectl exec -t $IIS_POD -- powershell -command 'iwr -UseBasicParsing  -TimeoutSec 5 http://nginx-svc'
```

## apply policies to tighten application access

Allow DNS access for all PODs in `default` namespace.

```bash
# label kube-system namespace to target it in policies
kubectl label ns kube-system dnshost=true
kubectl get ns kube-system --show-labels
# apply DNS policy that targets kube-system namespace
kubectl apply -f policy/k8s.allow-dns.yaml
# service names should be resolvable
kubectl exec -t netshoot -- sh -c 'SVC=iis-svc; nslookup $SVC'
IIS_POD=$(kubectl get pod -l run=iis -o jsonpath='{.items[*].metadata.name}')
kubectl exec -t $IIS_POD -- powershell -command 'Resolve-DnsName -Name nginx-svc'
```

Allow only `iis` PODs to access `nginx` service.

```bash
# apply policy to allow only iis PODs to access nginx service
kubectl apply -f policy/k8s.allow-iis-egress-to-nginx.policy.yaml
kubectl apply -f policy/k8s.allow-nginx-ingress-from-iis.yaml
# iis POD should be able to curl nginx-svc
kubectl exec -t $IIS_POD -- powershell -command 'iwr -UseBasicParsing  -TimeoutSec 5 http://nginx-svc'
# netshoot POD should not be able to curl nginx-svc
kubectl exec -t netshoot -- sh -c 'SVC=nginx-svc; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
```

Allow `netshoot` POD to access `iis` PODs, and then deploy Calico ingress policy to prevent `netshoot` from accessing the `iis` PODs. You'll need to [install `calicoctl`](https://docs.projectcalico.org/getting-started/clis/calicoctl/install) to apply the Calico policy

```bash
# apply policy to allow only netshoot POD to access iis service
kubectl apply -f policy/k8s.allow-netshoot-egress-to-iis.yaml
# netshoot POD should be able to curl iis-svc
kubectl exec -t netshoot -- sh -c 'SVC=iis-svc; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
# apply Calico policies to allow iis service access for any POD but netshoot
# you'll need to use 'calicoctl' to apply the Calico policy: https://docs.projectcalico.org/getting-started/clis/calicoctl/install
DATASTORE_TYPE=kubernetes calicoctl apply -f policy/calico.allow-iis-ingress-except-netshoot.policy.yaml
DATASTORE_TYPE=kubernetes calicoctl apply -f policy/calico.allow-nginx-egress-to-iis.policy.yaml
# now netshoot POD should not be able to curl iis-svc
kubectl exec -t netshoot -- sh -c 'SVC=iis-svc; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
# but nginx POD should be able to access iis-svc
NGINX_POD=$(kubectl get pod -l run=nginx -o jsonpath='{.items[*].metadata.name}')
kubectl exec -t $NGINX_POD -- sh -c 'SVC=iis-svc; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
```

## troubleshooting

### missing AWS metadata route

Sometimes AWS metadata route can be removed when Calico gets installed. If there are applications that rely on AWS metadata route, add it to the routing table.

```powershell
# view existing routes
Get-NetRoute
# retrieve interface index
Get-NetAdapter
$IfaceIndex='x' # use index number from Get-NetAdapter output
# add AWS metadata route
New-NetRoute -DestinationPrefix 169.254.169.254/32 -InterfaceIndex $IfaceIndex
```

### containers get stuck in `CreatingContainer` state

If some configuration settings were not set correctly, you may see containers get stuck in `ContainerCreating` or `Pending` state. Inspect Calico logs.

```powershell
cd C:\TigeraCalico
# list kubelet and kube-proxy logs
ls .\logs\
# get last N lines from a log file
gc .\logs\tigera-node.err.log -Tail 30
gc .\logs\tigera-node.log -Tail 30
```

One misconfiguration that can lead to containers getting stuck in `ContainerCreating` state is misconfiguration of `$env:NODENAME` env var in `.\config.ps1`, `.\kubernetes\start-kubelet.ps1`, or `.\kubernetes\start-kube-proxy.ps1`.

```powershell
# make sure RemoteAccess service is running. If not, set its StartType to "Automatic" and start the service.
Get-Service RemoteAccess | select -Property name,status,starttype
Set-Service -Name RemoteAccess -ComputerName . -StartupType "Automatic"
Start-Service RemoteAccess
##########################################
####### C:\TigeraCalico\config.ps1 #######
##########################################
# make sure $env:NODENAME variable is set to correct host name (on AWS it should be set to node's internal DNS, e.g. 'ip-10-0-0-21.us-west-2.compute.internal')
$env:NODENAME = "ip-10-0-0-21.us-west-2.compute.internal"
############################################################
####### C:\TigeraCalico\kubernetes\start-kubelet.ps1 #######
############################################################
# find '--hostname-override=' and set to correct host name (on AWS it should be set to node's internal DNS, e.g. 'ip-10-0-0-21.us-west-2.compute.internal')
# find '--node-ip=' and set to host's main IP (e.g. '10.0.0.21')
$NodeIp = "10.0.0.21"
$NodeName = "ip-10-0-0-21.us-west-2.compute.internal"
$argList = @(`
    "--hostname-override=$NodeName", `
    "--node-ip=$NodeIp", `
    .....
)
###############################################################
####### C:\TigeraCalico\kubernetes\start-kube-proxy.ps1 #######
###############################################################
# find '--hostname-override=' and set to correct host name (on AWS it should be set to node's internal DNS, e.g. 'ip-10-0-0-21.us-west-2.compute.internal')
$NodeName = "ip-10-0-0-21.us-west-2.compute.internal"
$argList = @(`
    "--hostname-override=$NodeName", `
    .....
)
```

### reinstall Calico if needed

Stop `kubelet.exe` and `kube-proxy.exe` processes, then reinstall Calico and start back up `kubelet.exe` and `kube-proxy.exe` processes.

```powershell
cd C:\TigeraCalico\
.\uninstall-calico.ps1
.\install-calico.ps1
.\kubernetes\start-kubelet.ps1
.\kubernetes\start-kube-proxy.ps1
```

### `i/o timeout` for `kubectl exec` command

If you see the error `Error from server: error dialing backend: dial tcp XX.XX.XX.XX:10250: i/o timeout` while attempting to run `kubectl exec` command on a POD, verify that `kubelet` port `10250` is open in Windows firewall.

```powershell
# see if there is a firewall rule for port 10250
netsh advfirewall firewall show rule name=all | findstr /i localport | findstr 10250
# alternative way using powershell
## get all active rules for Public firewall profile
$rules=(Get-NetFirewallProfile -Name Public | Get-NetFirewallRule | where {$_.Enabled -eq "True"})
## check if any rule contains kubelet port
$rules | Get-NetFirewallPortFilter | where { $_.LocalPort -Eq "10250" }
# if no rule defined to open default kubelet port, add firewall rule
netsh advfirewall firewall add rule name="Kubelet port 10250" dir=in action=allow protocol=TCP localport=10250
````
