# Getting up and running with Calico for Windows

In this guide words `node` and `host` are interchangeable. As of release of Calico v3.16.0 [windows support](https://docs.projectcalico.org/release-notes/#windows-support) was added to the open sourced edition of Calico and can now be used free of charge.

>While the Calico installation and configuration instructions in this guide cover the commercial version of Calico for Windows, for open sourced version of the installation guide refer to [projectcalico documentation](https://docs.projectcalico.org/getting-started/windows-calico/).

## before you begin

Make sure to use the correct Windows version with build `18317+` if you want to use network policies on Windows. For [more details](https://docs.projectcalico.org/getting-started/windows-calico/limitations#service-clusterips-incompatible-with-selectorspod-ips-in-network-policy) about compatible Windows version builds refer to [projectcalico documentation](https://docs.projectcalico.org/getting-started/windows-calico/).

## high level tasks to install Calico for Windows

- provision four Ubuntu instances: one for k8s master, and four for k8s workers
- provision one or two Windows instances. For example, `Windows 1903` and `Windows 1909` with Containers feature installed
- prepare Ubuntu instances for k8s installation
- use `kubeadm` to install K8s Ubuntu instances
- [install Calico Enterprise v3.4.0+](https://docs.tigera.io/getting-started/kubernetes/quickstart)
- prepare Windows nodes to be joined to k8s cluster
- use `Calico for Windows` v3.4.0+ to install Calico on Windows nodes and join the nodes to k8s cluster
- test connectivity between Linux and Windows pods
- use network policies to tighten security

## provision k8s cluster

Follow one of the following instructions to provision an unmanaged k8s cluster:

- [provision k8s cluster in AWS](cluster/aws/README.md)
- [provision k8s cluster in Azure](cluster/azure/README.md)

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

Deploy default-deny policy. Once the policy is deployed PODs won't be able to communicate until policies explicitly allowing access are deployed.

```bash
kubectl apply -f policy/calico.global-default-deny.yaml
```

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

Reconfigure Kube DNS access policy to use the `security` tier

```bash
kubectl delete -f policy/k8s.allow-dns.yaml
# create tier and deploy allow-kube-dns policy
kubectl apply -f policy/tier-security.yaml
kubectl apply -f policy/calico.allow-kube-dns.yaml
```

Allow `netshoot` POD to access `iis` PODs, and then deploy Calico ingress policy to prevent `netshoot` from accessing the `iis` PODs. You'll need to [install `calicoctl`](https://docs.projectcalico.org/getting-started/clis/calicoctl/install) to apply the Calico policy

```bash
# apply policy to allow only netshoot POD to access iis service
kubectl apply -f policy/k8s.allow-netshoot-to-iis.yaml
# netshoot POD should be able to curl iis-svc
kubectl exec -t netshoot -- sh -c 'SVC=iis-svc; curl -m 5 -sI http://$SVC 2>/dev/null | grep -i http'
# apply Calico policies to allow iis service access from any POD but netshoot
# when using Calico Enterprise, you can use either kubectl or 'calicoctl' to apply the Calico policy: https://docs.projectcalico.org/getting-started/clis/calicoctl/install
DATASTORE_TYPE=kubernetes calicoctl apply -f policy/calico.allow-iis-ingress-except-netshoot.policy.yaml
kubectl apply -f policy/calico.allow-nginx-egress-to-iis.policy.yaml
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
# retrieve interface index for primary routes (assuming node's subnet is 172.16.0.0/24)
$PvtIpIfaceIndex = (Get-NetRoute -DestinationPrefix 172.16.0.* | select -First 1).InterfaceIndex
# add AWS metadata route
New-NetRoute -DestinationPrefix 169.254.169.254/32 -InterfaceIndex $PvtIpIfaceIndex
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
