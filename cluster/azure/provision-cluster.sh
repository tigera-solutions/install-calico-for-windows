#!/usr/bin/env bash

# Exit on error. Append "|| true" if you expect an error.
set -o errexit
# Exit on error inside any functions or subshells.
set -o errtrace
# Do not allow use of undefined vars. Use ${VAR:-} to use an undefined VAR
set -o nounset
# Catch the error in case one pipe command fails but next succeeds, e.g in `mysqldump |gzip`
set -o pipefail
# Turn on traces, useful while debugging but commented out by default
# set -o xtrace

# output colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)

# helper function to wait for instance to reach a running state
confirm_yn_input(){
  INPUT=${1:-''}
  SWITCH=true
  while $SWITCH; do
    yn=$(echo $INPUT | tr '[:upper:]' '[:lower:]')
    case $yn in
      n | y)
        SWITCH=false
        ;;
      *)
        read -p "enter 'y' or 'n' [y/n]: " INPUT
        ;;
    esac
  done
  echo $yn
}

# vars
RESOURCE_GROUP=${1:-'calient'}
LOCATION=${2:-'westus2'}
PROJECT_NAME=${3:-"c4w"}
SSH_PUB_KEY=${4:-"$(cat ~/.ssh/rsa_id.pub)"} # SSH public key
KUBE_VERSION=${5:-'v1.18.8'}
ARM_TEMPLATE=${6:-'arm/deploy.json'}
ARM_PARAMETERS=${7:-'arm/parameters.json'}
MASTER_CLOUD_CONFIG=${8:-'config/ubuntu-master-config.yaml'}
WORKER_CLOUD_CONFIG=${9:-'config/ubuntu-worker-config.yaml'}

if [[ $(az group exists -n $RESOURCE_GROUP) != true ]]; then
  echo $GREEN "creating resource group '$RESOURCE_GROUP' in location '$LOCATION'" $NORMAL
  az group create -n $RESOURCE_GROUP -l $LOCATION --output jsonc
else
  echo "resource group '$RESOURCE_GROUP' already exists, using the existing resource group."
fi

echo $GREEN "validating Azure deployment" $NORMAL
az deployment group validate --resource-group $RESOURCE_GROUP \
  --template-file $ARM_TEMPLATE \
  --parameters @$ARM_PARAMETERS \
  --parameters projectName=$PROJECT_NAME \
  --parameters masterConfig=@$MASTER_CLOUD_CONFIG \
  --parameters workerConfig=@$WORKER_CLOUD_CONFIG \
  --parameters adminPublicKey="$SSH_PUB_KEY" \
  --output jsonc \
  --only-show-errors

read -p "do you want to provision the infrastructure? [y/n]: " PROVISION
if [[ -z $PROVISION ]] || [[ "$(confirm_yn_input $PROVISION)" == "n" ]]; then
    echo $RED "script has been termited by the user" $NORMAL
    exit 1
fi

echo $GREEN "creating Azure deployment from ARM template" $NORMAL
az deployment group create --resource-group $RESOURCE_GROUP \
  --template-file $ARM_TEMPLATE \
  --parameters @$ARM_PARAMETERS \
  --parameters projectName=$PROJECT_NAME \
  --parameters masterConfig=@$MASTER_CLOUD_CONFIG \
  --parameters workerConfig=@$WORKER_CLOUD_CONFIG \
  --parameters adminPublicKey="$SSH_PUB_KEY" \
  --output jsonc

##########################################################################################################################################
BASEDIR=$(dirname "$0")
# helper scripts vars
KUBE_PACKAGE_NAME="kubernetes-node-windows-amd64.tar.gz"
CALICO_PACKAGE_NAME="tigera-calico-windows-v3.12.1.zip"
HELPER_PREFIX="helper"
# public IP of master0 instance
m0publicip=$(az network public-ip show -g $RESOURCE_GROUP --name "${PROJECT_NAME}-ip-master0" --query 'ipAddress' --output tsv)
#######################
# build helper script to upload assets to Linux node
#######################
# create script
HELPER_SCRIPT="${BASEDIR}/${HELPER_PREFIX}-upload-assets-to-master.sh"
echo $GREEN "generating upload-assets script ${HELPER_SCRIPT}" $NORMAL
cat > $HELPER_SCRIPT <<EOF
#!/usr/bin/env bash

SSH_KEY_PATH=\${1:-'\$HOME/.ssh/calico-az-id.pem'}
CALICO_ZIP=\${2:-'/tmp/tigera-calico-windows-v3.12.1.zip'}
MASTER_IP=\${3:-"$m0publicip"}
echo "uploading assets to the linux node (\$MASTER_IP)"
scp -i \${SSH_KEY_PATH} ./helper-prep-master-node.sh ./helper-prep-win-node.ps1 ./helper-configure-calico.ps1 \${CALICO_ZIP} azureuser@\$MASTER_IP:~/
EOF
#######################
# build helper script to download Kubernetes binaries onto Linux node
#######################
# create script
HELPER_SCRIPT="${BASEDIR}/${HELPER_PREFIX}-prep-master-node.sh"
echo $GREEN "generating get-kube-bin script ${HELPER_SCRIPT}" $NORMAL
cat > $HELPER_SCRIPT <<EOF
#!/usr/bin/env bash

echo "configuring kubeadm config"
sudo cp /root/kubeadm/kubeadm-config.yaml ./
sudo chown azureuser:azureuser ./kubeadm-config.yaml
# export k8s control plane endpoint var
export MASTER_PUB_IP=$m0publicip
#sed -i -- 's/\\#controlPlaneEndpoint:\\ \$MASTER_PUB_IP/controlPlaneEndpoint: \$MASTER_PUB_IP/g' ./kubeadm-config.yaml
envsubst < kubeadm-config.yaml > cluster-config.yaml
echo "downloading Kubernetes binaries for version '$KUBE_VERSION' ..."
curl -kL -o \$HOME/$KUBE_PACKAGE_NAME https://dl.k8s.io/$KUBE_VERSION/$KUBE_PACKAGE_NAME
echo "initialize k8s cluster using the following command:"
echo -e "\t sudo kubeadm init --config=cluster-config.yaml"
EOF
#######################
# build helper script to prepare Windows node
#######################
# create script
HELPER_SCRIPT="${BASEDIR}/${HELPER_PREFIX}-prep-win-node.ps1"
echo $GREEN "generating prep-win-node script ${HELPER_SCRIPT}" $NORMAL
cat > $HELPER_SCRIPT << EOF
[CmdletBinding()]
param(
  \$KubeletPort=10250
)

echo "open kubelet port 10250"
netsh advfirewall firewall add rule name="Kubelet port \$KubeletPort" dir=in action=allow protocol=TCP localport=\$KubeletPort
echo 'Check and install required Windows features'
Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN
if ((Get-WindowsFeature RemoteAccess).InstallState -notlike 'installed'){
  echo "installing feature 'RemoteAccess'"
  Install-WindowsFeature RemoteAccess
}
if ((Get-WindowsFeature Routing).InstallState -notlike 'installed'){
  echo "installing feature 'Routing'"
  Install-WindowsFeature Routing
}
if ((Get-WindowsFeature DirectAccess-VPN).InstallState -notlike 'installed'){
  echo "installing feature 'DirectAccess-VPN'"
  Install-WindowsFeature DirectAccess-VPN
}
Get-WindowsFeature RemoteAccess,Routing,DirectAccess-VPN
Set-Service -Name RemoteAccess -ComputerName . -StartupType "Automatic"
Get-Service RemoteAccess | select -Property name,status,starttype
echo 'Rebooting node ...'
Restart-Computer -Confirm
EOF
#######################
# build helper script to configure Calico for Windows
#######################
# create script
HELPER_SCRIPT="${BASEDIR}/${HELPER_PREFIX}-configure-calico.ps1"
echo $GREEN "generating configure-calico script ${HELPER_SCRIPT}" $NORMAL
cat > $HELPER_SCRIPT << EOF
[CmdletBinding()]
param(
  \$Nodename="",
  \$MasterIP="$m0publicip",
  \$SshKeyPath="\$HOME\az_id",
  \$CalicoPackageName="tigera-calico-windows-v3.12.1.zip",
  \$KubernetesVersion="v1.18.5",
  \$KubePackageName="kubernetes-node-windows-amd64.tar.gz",
  \$CniDir="c:\k\cni",
  \$CalicoBackend="vxlan",
  \$DatastoreType="kubernetes",
  \$CalicoDir="C:\TigeraCalico"
)

if ((Get-Service RemoteAccess).Status -notlike 'running'){
  write-host -ForegroundColor Red -BackgroundColor Black "'RemoteAccess' service is not running. It must be running in order to proceed. Exiting configuration process..."
  exit 1
}
cd \$HOME\Downloads
echo "download Calico for Windows package from linux node"
scp.exe -o StrictHostKeyChecking=no -i \$SshKeyPath azureuser@\$MasterIP\`:~/$CALICO_PACKAGE_NAME ./
echo "extract Calico for Windows components"
Expand-Archive \$HOME\Downloads\\$CALICO_PACKAGE_NAME c:\\
echo "build Kubernetes pause image"
\$WIN_CORE_VER=\$((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId)
docker pull mcr.microsoft.com/windows/nanoserver:\$WIN_CORE_VER
docker tag mcr.microsoft.com/windows/nanoserver:\${WIN_CORE_VER} mcr.microsoft.com/windows/nanoserver:latest
cd \$HOME\Documents
mkdir pause; cd pause;
iwr -usebasicparsing -outfile Dockerfile -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile
docker build -t kubeletwin/pause .
# create kube folders
mkdir c:\k; mkdir c:\k\cni; mkdir c:\k\cni\config;
cd \$HOME\Downloads
echo "download Kubernetes binaries package"
scp.exe -o StrictHostKeyChecking=no -i \$SshKeyPath azureuser@\$MasterIP\`:~/$KUBE_PACKAGE_NAME ./
echo "unpack Kubernetes components"
tar.exe -xf $KUBE_PACKAGE_NAME
# copy kube components to c:\k path
cp .\kubernetes\node\bin\*.exe c:\k
echo "donload kubeconfig file"
\$env:KUBECONFIG="c:\k\config"
scp.exe -o StrictHostKeyChecking=no -i \$SshKeyPath azureuser@\$MasterIP\`:~/.kube/config \$env:KUBECONFIG
echo "check kubectl connection to control plane"
Set-Alias -Name kubectl -Value "c:\k\kubectl.exe"
kubectl version
echo "download CNI plugins"
iwr -usebasicparsing -outfile \$CniDir\flannel.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe
iwr -usebasicparsing -outfile \$CniDir\win-bridge.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe
iwr -usebasicparsing -outfile \$CniDir\host-local.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe
# echo "configure Calico"
# if ([string]::IsNullOrEmpty(\$Nodename)){
#   if (\$CalicoBackend -match "bgp"){
#     \$Nodename=(read-host "provide node name (i.e. internal DNS name, e.g. \`"ip-10-0-0-21.us-west-2.compute.internal\`")")}
#   else{
#     try{
#       \$Nodename=(curl -UseBasicParsing http://169.254.169.254/latest/meta-data/local-hostname).Content
#     }
#     catch{
#       Write-Host -ForegroundColor Red -BackgroundColor Black "Failed to retrieve hosts's internal DNS name."
#     \$Nodename=(read-host "provide node name (i.e. internal DNS name, e.g. \`"ip-10-0-0-21.us-west-2.compute.internal\`")")
#     }}
# }
echo "configuring C:\TigeraCalico\config.ps1"
(cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:CALICO_NETWORKING_BACKEND(.*?)\$',"\`\$env\`:CALICO_NETWORKING_BACKEND=\`"\$CalicoBackend\`"" | Set-Content c:\TigeraCalico\config.ps1
# (cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:NODENAME(.*?)\$',"\`\$env\`:NODENAME=\`"\$Nodename\`"" | Set-Content c:\TigeraCalico\config.ps1
(cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:CALICO_DATASTORE_TYPE(.*?)\$',"\`\$env\`:CALICO_DATASTORE_TYPE=\`"\$DatastoreType\`"" | Set-Content c:\TigeraCalico\config.ps1
echo "install Calico"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\install-calico.ps1 -Wait
# Invoke-Command -FilePath \$CalicoDir\\install-calico.ps1
echo "start kubelet"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\kubernetes\\start-kubelet.ps1
echo "start kube-proxy"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\kubernetes\\start-kube-proxy.ps1
# echo "ensuring AWS metadata route"
# \$MetaRoute='169.254.169.254/32'
# \$Route=(Get-NetRoute -DestinationPrefix \$MetaRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue)
# if (\$Route){
#   echo "AWS metadata route '\$MetaRoute' exists"
# }else{
#   echo "AWS metadata route is missing. Adding the routes '\$MetaRoute'"
#   echo "note, the command looks for a specific network adapter naming. Adjust the query if needed."
#   New-NetRoute -DestinationPrefix \$MetaRoute -InterfaceIndex (Get-NetAdapter | where {\$_.Name -like "*(ethernet 2)*"} | select -ExpandProperty ifIndex)
# }
EOF
