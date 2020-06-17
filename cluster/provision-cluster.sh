#!/usr/bin/env bash

# Exit on error. Append "|| true" if you expect an error.
set -o errexit
# Exit on error inside any functions or subshells.
set -o errtrace
# Do not allow use of undefined vars. Use ${VAR:-} to use an undefined VAR
set -o nounset
# Catch the error in case mysqldump fails (but gzip succeeds) in `mysqldump |gzip`
set -o pipefail
# Turn on traces, useful while debugging but commented out by default
# set -o xtrace

# output colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)

# helper function to wait for instance to reach a running state
wait_for_instance(){
  instance=${1:-''}
  for i in {1..10}; do
    state=$(aws ec2 describe-instances --instance-ids $instance --query "Reservations[].Instances[?(@.InstanceId=='$instance')].State.Name" --output text)
    if [[ "$state" == "running" ]]; then
      echo "instance $instance is up and running"
      break
    else
      echo "waiting for instance $instance to be running"
      sleep 10s
    fi
  done
}

# vars
REGION=${1:-'us-west-2'}
OWNER=${2:-'calico'}
IAM_ROLE_MASTER=${3:-"$OWNER-k8s-master-role"} # AWS instance profile
IAM_ROLE_WORKER=${4:-"$OWNER-k8s-worker-role"} # AWS instance profile
IAM_PROFILE_MASTER=${5:-"$OWNER-k8s-master-instance-profile"} # AWS instance profile
IAM_PROFILE_WORKER=${6:-"$OWNER-k8s-worker-instance-profile"} # AWS instance profile
KEY_PAIR_NAME=${7:-"$OWNER-aws-ec2"} # AWS key pair
CLUSTER_ID=${8:-''} # use when building multiple clusters in the same AWS account

if [[ $(aws ec2 describe-key-pairs --key-names $KEY_PAIR_NAME 2>&1 | grep -c 'InvalidKeyPair.NotFound') == 1 ]]; then
  echo "no key pair '$KEY_PAIR_NAME' found"
  echo $GREEN "creating key-pair with name '$KEY_PAIR_NAME'" $NORMAL
  aws ec2 create-key-pair --key-name $KEY_PAIR_NAME --query 'KeyMaterial' --output text > "$KEY_PAIR_NAME.pem"
else
  echo "found key pair '$KEY_PAIR_NAME', using existing key pair"
fi

if [[ $(aws iam get-role --role-name $IAM_ROLE_MASTER 2>&1 | grep -c 'NoSuchEntity') == 1 ]]; then
  echo $GREEN "creating IAM role and policy for master nodes" $NORMAL
  aws iam create-role --role-name $IAM_ROLE_MASTER --assume-role-policy-document file://ec2-role-trust-policy.json
  aws iam put-role-policy --role-name $IAM_ROLE_MASTER --policy-name $OWNER-k8s-master-policy --policy-document file://k8s-master-access-policy.json
else
  echo "found role '$IAM_ROLE_MASTER', using existing role"
fi
if [[ $(aws iam get-instance-profile --instance-profile-name $IAM_PROFILE_MASTER 2>&1 | grep -c 'NoSuchEntity') == 1 ]]; then
  echo $GREEN "creating instance profile for master nodes" $NORMAL
  aws iam create-instance-profile --instance-profile-name $IAM_PROFILE_MASTER
  aws iam add-role-to-instance-profile --instance-profile-name $IAM_PROFILE_MASTER --role-name $IAM_ROLE_MASTER
else
  echo "found profile '$IAM_PROFILE_MASTER', using existing profile for master nodes"
fi

if [[ $(aws iam get-role --role-name $IAM_ROLE_WORKER 2>&1 | grep -c 'NoSuchEntity') == 1 ]]; then
  echo "role '$IAM_ROLE_WORKER' does not exist"
  echo $GREEN "creating IAM role and policy for worker nodes" $NORMAL
  aws iam create-role --role-name $IAM_ROLE_WORKER --assume-role-policy-document file://ec2-role-trust-policy.json
  aws iam put-role-policy --role-name $IAM_ROLE_WORKER --policy-name $OWNER-k8s-worker-policy --policy-document file://k8s-worker-access-policy.json
else
  echo "found role '$IAM_ROLE_WORKER', using existing role"
fi
if [[ $(aws iam get-instance-profile --instance-profile-name $IAM_PROFILE_WORKER 2>&1 | grep -c 'NoSuchEntity') == 1 ]]; then
  echo $GREEN "creating instance profile for worker nodes" $NORMAL
  aws iam create-instance-profile --instance-profile-name $IAM_PROFILE_WORKER
  aws iam add-role-to-instance-profile --instance-profile-name $IAM_PROFILE_WORKER --role-name $IAM_ROLE_WORKER
else
  echo "found profile '$IAM_PROFILE_WORKER', using existing profile for worker nodes"
fi

# project name var
export PROJ_NAME="c4w${CLUSTER_ID}"
#############################################
# configure VPC, subnets, igw, RouteTable, SG
#############################################
# create VPC and get its Id. use sed to remove quotes from returned Id string
echo $GREEN "creating VPC" $NORMAL
vpcid=$(aws ec2 create-vpc --region ${REGION} --cidr-block '10.0.0.0/16' --output json | jq '.Vpc.VpcId'| sed -e 's/^"//' -e 's/"$//')
# tag VPC
echo $GREEN "tagging VPC: $vpcid" $NORMAL
aws ec2 create-tags --resources $vpcid --tags Key=creator,Value=$OWNER
aws ec2 create-tags --resources $vpcid --tags Key=Name,Value=$OWNER-$PROJ_NAME-vpc
# this tag is needed so that some kube objects can manipulate AWS resources (e.g. LB)
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $vpcid
# create subnet1 for the VPC and get its Id
echo $GREEN "creating Subnet1" $NORMAL
subnet1id=$(aws ec2 create-subnet --vpc-id $vpcid --cidr-block 10.0.0.0/24 --availability-zone ${REGION}a --output json | jq '.Subnet.SubnetId'| sed -e 's/^"//' -e 's/"$//')
# tag subnet
echo $GREEN "tagging Subnet1: $subnet1id" $NORMAL
aws ec2 create-tags --resources $subnet1id --tags Key=creator,Value=$OWNER
aws ec2 create-tags --resources $subnet1id --tags Key=Name,Value=$OWNER-$PROJ_NAME-subnet1
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $subnet1id
# must set public IP mapping so that you can SSH into the instances. you canNOT change this later.
echo $GREEN "tweaking Subnet1 to have public IP on instance launch" $NORMAL
aws ec2 modify-subnet-attribute --subnet-id $subnet1id --map-public-ip-on-launch
# create and tag Internet Gateway to allow access to the instances from outside of AWS (e.g. SSH)
echo $GREEN "creating IGW" $NORMAL
igwid=$(aws ec2 create-internet-gateway --output json | jq '.InternetGateway.InternetGatewayId' | sed -e 's/^"//' -e 's/"$//')
echo $GREEN "tagging IGW: $igwid" $NORMAL
aws ec2 create-tags --resources $igwid --tags Key=creator,Value=$OWNER
aws ec2 create-tags --resources $igwid --tags Key=Name,Value=$OWNER-$PROJ_NAME-IGW
# this tag is used in AWS cloud provider. Without it the cloud provider won't work correctly.
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $igwid
# attach IGW to VPC
echo $GREEN "attaching IGW to VPC" $NORMAL
aws ec2 attach-internet-gateway --vpc-id $vpcid --internet-gateway-id $igwid --output json
# create and tag RouteTable for VPC
echo $GREEN "creating RouteTable" $NORMAL
rtbid=$(aws ec2 create-route-table --vpc-id $vpcid --output json | jq '.RouteTable.RouteTableId'| sed -e 's/^"//' -e 's/"$//')
echo $GREEN "tagging RouteTable: $rtbid" $NORMAL
aws ec2 create-tags --resources $rtbid --tags Key=creator,Value=$OWNER
aws ec2 create-tags --resources $rtbid --tags Key=Name,Value=$OWNER-$PROJ_NAME-RT
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $rtbid
# associate RouteTable with the subnet
echo $GREEN "associating RouteTable with Subnet" $NORMAL
aws ec2 associate-route-table  --subnet-id $subnet1id --route-table-id $rtbid --output json
# create route to allow all traffic
echo $GREEN "creating Route" $NORMAL
aws ec2 create-route --route-table-id $rtbid --destination-cidr-block 0.0.0.0/0 --gateway-id $igwid --output json
# create Security Group (SG)
echo $GREEN "creating Security Group" $NORMAL
sgid=$(aws ec2 create-security-group --description "$OWNER-LAB-POD-SG" --group-name $OWNER-$PROJ_NAME-SG --vpc-id $vpcid --output json | jq '.GroupId'| sed -e 's/^"//' -e 's/"$//')
# open a few ports in the SG
echo $GREEN "opening ports in SG: $sgid" $NORMAL
aws ec2 authorize-security-group-ingress --group-id $sgid --protocol tcp --port 3389 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $sgid --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $sgid --protocol tcp --port 6443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $sgid --protocol all --source-group $sgid
#############################################
# configure variables to build VMs
#############################################
# export vars to configure nodes
IP_BLOCK=1
export MASTER0=master1
export M0IP=10.0.0.${IP_BLOCK}0
IP_BLOCK=2
export W1=worker1
export W1IP=10.0.0.${IP_BLOCK}0
export W2=worker2
export W2IP=10.0.0.${IP_BLOCK}1
export W3=worker3
export W3IP=10.0.0.${IP_BLOCK}2
# vars for host VM
IP_BLOCK=4
export HOST=host1
export HIP=10.0.0.${IP_BLOCK}0
# Ubuntu 18.04 ami
export IMAGE_ID=ami-0b199ce4c7f1a6dd2
# Windows 2019 (1809) Base with Containers
export WIN_IMAGE_ID=ami-001589977a146ef31
# Windows 1903 core with Containers
export WIN1903_IMAGE_ID=ami-060a4b0c07c89ef0d
# Windows 1909 core with Containers
export WIN1909_IMAGE_ID=ami-028cdf199fb6c2daf
# Windows instance predefined password
# NOTE: used for second Windows (i.e. worker3) instance only
export WIN_PASSWORD='P@ssw0rd1234'
# Windows 1909 core base
# export WIN1909_IMAGE_ID=ami-0c7f9668831d801cd
# Windows 1909 core with Containers
# export WIN1909_IMAGE_ID=ami-028cdf199fb6c2daf
# VM disk config
DISK_CONFIG='DeviceName=/dev/sda1,Ebs={VolumeSize=35,DeleteOnTermination=true}'
WIN_DISK_CONFIG='DeviceName=/dev/sda1,Ebs={VolumeSize=60,DeleteOnTermination=true}'
#############################################
# save objects info
#############################################
# write resource IDs to a file
BASEDIR=$(dirname "$0")
RES_FILE="$BASEDIR/${OWNER}-${PROJ_NAME}-resources"
# assign and render resource IDs
echo $GREEN
echo VPC=$vpcid > ${RES_FILE}
echo SUBNET1=$subnet1id >> ${RES_FILE}
echo IGW=$igwid >> ${RES_FILE}
echo RT=$rtbid >> ${RES_FILE}
echo SG=$sgid >> ${RES_FILE}
echo $NORMAL
#############################################
# create and configure VMs
# NOTE: to use instance hibernation setting, the disk must have enough space to store entire RAM footprint on it.
# you can either use DISK_CONFIG var to configure disk size.
#############################################
# Master0:
##########
echo $GREEN "creating instance $MASTER0" $NORMAL
m0id=$(aws ec2 run-instances --key-name $KEY_PAIR_NAME --image-id $IMAGE_ID --instance-type r5.large --hibernation-options Configured=true --security-group-ids $sgid --private-ip-address $M0IP --subnet $subnet1id --block-device-mappings $DISK_CONFIG --iam-instance-profile Name=${IAM_PROFILE_MASTER} --user-data file://cloud-config.yaml --output json | jq '.Instances[0].InstanceId'| sed -e 's/^"//' -e 's/"$//')
echo "$MASTER0 instanceID = $m0id" >> ${RES_FILE}
echo $GREEN "tagging instance $MASTER0" $NORMAL
aws ec2 create-tags --tags Key=creator,Value=$OWNER --resources $m0id
aws ec2 create-tags --tags Key=Name,Value=$OWNER-$PROJ_NAME-m0 --resources $m0id
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $m0id
# disable source destination check to allow traffic packet flow (e.g. ICMP)
echo $GREEN "disabling source-dest-check for $MASTER0" $NORMAL
aws ec2 modify-instance-attribute --source-dest-check "{\"Value\": false}" --instance-id $m0id
# get public IP
echo $GREEN "getting public IP for $MASTER0" $NORMAL
m0publicip=$(aws ec2 describe-instances --instance-ids $m0id --output json | jq '.Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' | sed -e 's/^"//' -e 's/"$//')
##########
# Worker1:
##########
# wait for the instance to be running
wait_for_instance $m0id
echo $GREEN "creating instance $W1" $NORMAL
w1id=$(aws ec2 run-instances --key-name $KEY_PAIR_NAME --image-id $IMAGE_ID --instance-type r5.large --hibernation-options Configured=true --security-group-ids $sgid --private-ip-address $W1IP --subnet $subnet1id --block-device-mappings $DISK_CONFIG --iam-instance-profile Name=${IAM_PROFILE_WORKER} --user-data file://cloud-config.yaml --output json | jq '.Instances[0].InstanceId'| sed -e 's/^"//' -e 's/"$//')
echo "$W1 instanceID = $w1id" >> ${RES_FILE}
echo $GREEN "tagging instance $W1" $NORMAL
aws ec2 create-tags --tags Key=creator,Value=$OWNER --resources $w1id
aws ec2 create-tags --tags Key=Name,Value=$OWNER-$PROJ_NAME-w1 --resources $w1id
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $w1id
# disable source destination check to allow traffic packet flow (e.g. ICMP)
echo $GREEN "disabling source-dest-check for $W1" $NORMAL
aws ec2 modify-instance-attribute --source-dest-check "{\"Value\": false}" --instance-id $w1id
echo $GREEN "getting public IP for $W1" $NORMAL
w1publicip=$(aws ec2 describe-instances --instance-ids $w1id --output json | jq '.Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' | sed -e 's/^"//' -e 's/"$//')
##########
# Worker2:
##########
# wait for the instance to be running
wait_for_instance $w1id
echo $GREEN "creating instance $W2" $NORMAL
# windows password is set in win-user-data.xml
w2id=$(aws ec2 run-instances --key-name $KEY_PAIR_NAME --image-id $WIN1903_IMAGE_ID --instance-type r5.large --security-group-ids $sgid --private-ip-address $W2IP --subnet $subnet1id --block-device-mappings $WIN_DISK_CONFIG --iam-instance-profile Name=${IAM_PROFILE_WORKER} --output json | jq '.Instances[0].InstanceId'| sed -e 's/^"//' -e 's/"$//')
echo "$W2 instanceID = $w2id" >> ${RES_FILE}
echo $GREEN "tagging instance $W2" $NORMAL
aws ec2 create-tags --tags Key=creator,Value=$OWNER --resources $w2id
aws ec2 create-tags --tags Key=Name,Value=$OWNER-$PROJ_NAME-w2 --resources $w2id
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $w2id
echo $GREEN "disabling source-dest-check for $W2" $NORMAL
aws ec2 modify-instance-attribute --source-dest-check "{\"Value\": false}" --instance-id $w2id
echo $GREEN "getting public IP for $W2" $NORMAL
w2publicip=$(aws ec2 describe-instances --instance-ids $w2id --output json | jq '.Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' | sed -e 's/^"//' -e 's/"$//')
##########
# Worker3:
##########
# wait for the instance to be running
# wait_for_instance $w2id
echo $GREEN "creating instance $W3" $NORMAL
# windows password is set in win-user-data.xml
w3id=$(aws ec2 run-instances --key-name $KEY_PAIR_NAME --image-id $WIN1909_IMAGE_ID --instance-type r5.large --security-group-ids $sgid --private-ip-address $W3IP --subnet $subnet1id --block-device-mappings $WIN_DISK_CONFIG --iam-instance-profile Name=${IAM_PROFILE_WORKER} --user-data "<powershell>net user Administrator '$WIN_PASSWORD'</powershell>" --output json | jq '.Instances[0].InstanceId'| sed -e 's/^"//' -e 's/"$//')
echo "$W3 instanceID = $w3id" >> ${RES_FILE}
echo $GREEN "tagging instance $W3" $NORMAL
aws ec2 create-tags --tags Key=creator,Value=$OWNER --resources $w3id
aws ec2 create-tags --tags Key=Name,Value=$OWNER-$PROJ_NAME-w3 --resources $w3id
aws ec2 create-tags --tags Key=kubernetes.io/cluster/${OWNER}cluster1,Value=${OWNER}cluster1 --resources $w3id
echo $GREEN "disabling source-dest-check for $W3" $NORMAL
aws ec2 modify-instance-attribute --source-dest-check "{\"Value\": false}" --instance-id $w3id
echo $GREEN "getting public IP for $W3" $NORMAL
w3publicip=$(aws ec2 describe-instances --instance-ids $w3id --output json | jq '.Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' | sed -e 's/^"//' -e 's/"$//')

############################
# capture pub IPs
############################
echo "$MASTER0=$m0publicip" >> ${RES_FILE}
echo "$W1=$w1publicip" >> ${RES_FILE}
echo "$W2=$w2publicip" >> ${RES_FILE}
echo "$W3=$w3publicip" >> ${RES_FILE}
############################
# print created objects' IDs
############################
echo -e "# project name: $PROJ_NAME"
echo -e "$MASTER0:\t\t$m0publicip"
echo -e "$W1:\t\t$w1publicip"
echo -e "$W2:\t\t$w2publicip"
echo -e "$W3:\t\t$w3publicip"
echo -e "$MASTER0:\t\t$M0IP"
echo -e "$W1 :\t\t$W1IP"
echo -e "$W2 :\t\t$W2IP"
echo -e "$W3 :\t\t$W3IP"
echo "# IAM roles, instance profiles, policies"
echo -e "master role:\t\t\t$IAM_ROLE_MASTER"
echo -e "master instance profile:\t$IAM_PROFILE_MASTER"
echo -e "master role policy:\t\t$OWNER-k8s-master-policy"
echo -e "worker role:\t\t\t$IAM_ROLE_WORKER"
echo -e "worker instance profile:\t$IAM_PROFILE_WORKER"
echo -e "worker role policy:\t\t$OWNER-k8s-worker-policy"
#######################
# build clean up script
#######################
INSTANCE_ARR="$w1id $w2id $w3id $m0id"
# create cleanup script
CLEANUP_SCRIPT="${BASEDIR}/${OWNER}-${PROJ_NAME}-cleanup.sh"
echo $GREEN "generating cleanup script ${CLEANUP_SCRIPT}" $NORMAL
# echo "#!/usr/bin/env bash" > ${CLEANUP_SCRIPT}

# echo "aws ec2 terminate-instances --instance-ids $INSTANCE_ARR" >> ${CLEANUP_SCRIPT}
# echo "for instance in $INSTANCE_ARR; do" >> ${CLEANUP_SCRIPT}
cat >> ${CLEANUP_SCRIPT} << EOF
#!/usr/bin/env bash

aws ec2 terminate-instances --instance-ids $INSTANCE_ARR > /dev/null 2>&1
for instance in $INSTANCE_ARR; do
  for i in {1..10}; do
    state=\$(aws ec2 describe-instances --instance-ids \$instance --query "Reservations[].Instances[?(@.InstanceId=='\$instance')].State.Name" --output text)
    if [[ "\$state" == "terminated" ]]; then
      echo "instance \$instance has been terminated"
      break
    else
      echo "waiting for instance \$instance to terminate"
      sleep 10s
    fi
  done
done

echo -e 'removing:\n\t SG: $sgid\n\t Subnet: $subnet1id\n\t RouteTable: $rtbid\n\t IGW: $igwid\n\t VPC: $vpcid'
aws ec2 delete-security-group --group-id $sgid
aws ec2 delete-subnet --subnet-id $subnet1id
aws ec2 delete-route-table --route-table-id $rtbid
aws ec2 detach-internet-gateway --internet-gateway-id $igwid --vpc-id $vpcid
aws ec2 delete-internet-gateway --internet-gateway-id $igwid
aws ec2 delete-vpc --vpc-id $vpcid

echo -e 'removing IAM roles:$IAM_ROLE_MASTER $IAM_ROLE_WORKER\n\t instance profiles: $IAM_PROFILE_MASTER $IAM_PROFILE_WORKER\n\t policies: $OWNER-k8s-master-policy $OWNER-k8s-worker-policy\n\t key-pair: $KEY_PAIR_NAME'
aws iam remove-role-from-instance-profile --instance-profile-name $IAM_PROFILE_MASTER --role-name $IAM_ROLE_MASTER
aws iam remove-role-from-instance-profile --instance-profile-name $IAM_PROFILE_WORKER --role-name $IAM_ROLE_WORKER
aws iam delete-role-policy --role-name $IAM_ROLE_MASTER --policy-name $OWNER-k8s-master-policy
aws iam delete-role-policy --role-name $IAM_ROLE_WORKER --policy-name $OWNER-k8s-worker-policy
aws iam delete-role --role-name $IAM_ROLE_MASTER
aws iam delete-role --role-name $IAM_ROLE_WORKER
aws iam delete-instance-profile --instance-profile-name $IAM_PROFILE_MASTER
aws iam delete-instance-profile --instance-profile-name $IAM_PROFILE_WORKER
aws ec2 delete-key-pair --key-name $KEY_PAIR_NAME
EOF
##########################################################################################################################################
# helper scripts vars
KUBE_VERSION="v1.18.2"
KUBE_PACKAGE_NAME="kubernetes-node-windows-amd64.tar.gz"
CALICO_PACKAGE_NAME="tigera-calico-windows-v3.12.1.zip"
HELPER_PREFIX="helper"
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
# export k8s control plane endpoint var
export MASTER_PUB_IP=$m0publicip
sed -i -- 's/\\#controlPlaneEndpoint:\\ \$MASTER_PUB_IP/controlPlaneEndpoint: \$MASTER_PUB_IP/g' ./kubeadm-config.yaml
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
  \$MasterIP,
  \$SshKeyPath="\$HOME\calico-aws-ec2.pem",
  \$CalicoPackageName="tigera-calico-windows-v3.12.1.zip",
  \$KubernetesVersion="v1.18.2",
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
scp.exe -o StrictHostKeyChecking=no -i \$HOME\\$KEY_PAIR_NAME.pem ubuntu@$m0publicip\`:~/$CALICO_PACKAGE_NAME ./
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
scp.exe -o StrictHostKeyChecking=no -i \$HOME\\$KEY_PAIR_NAME.pem ubuntu@$m0publicip\`:~/$KUBE_PACKAGE_NAME ./
echo "unpack Kubernetes components"
tar.exe -xf $KUBE_PACKAGE_NAME
# copy kube components to c:\k path
cp .\kubernetes\node\bin\*.exe c:\k
echo "donload kubeconfig file"
\$env:KUBECONFIG="c:\k\config"
scp.exe -o StrictHostKeyChecking=no -i \$HOME\\$KEY_PAIR_NAME.pem ubuntu@$m0publicip\`:~/.kube/config \$env:KUBECONFIG
echo "check kubectl connection to control plane"
Set-Alias -Name kubectl -Value "c:\k\kubectl.exe"
kubectl version
echo "download CNI plugins"
iwr -usebasicparsing -outfile \$CniDir\flannel.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/flannel.exe
iwr -usebasicparsing -outfile \$CniDir\win-bridge.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/win-bridge.exe
iwr -usebasicparsing -outfile \$CniDir\host-local.exe -uri https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe
echo "configure Calico"
if ([string]::IsNullOrEmpty(\$Nodename)){
  if (\$CalicoBackend -match "bgp"){
    \$Nodename=(read-host "provide node name (i.e. internal DNS name, e.g. \`"ip-10-0-0-21.us-west-2.compute.internal\`")")}
  else{
    try{
      \$Nodename=(curl -UseBasicParsing http://169.254.169.254/latest/meta-data/local-hostname).Content
    }
    catch{
      Write-Host -ForegroundColor Red -BackgroundColor Black "Failed to retrieve hosts's internal DNS name."
    \$Nodename=(read-host "provide node name (i.e. internal DNS name, e.g. \`"ip-10-0-0-21.us-west-2.compute.internal\`")")
    }}
}
echo "configuring C:\TigeraCalico\config.ps1"
(cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:CALICO_NETWORKING_BACKEND(.*?)\$',"\`\$env\`:CALICO_NETWORKING_BACKEND=\`"\$CalicoBackend\`"" | Set-Content c:\TigeraCalico\config.ps1
(cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:NODENAME(.*?)\$',"\`\$env\`:NODENAME=\`"\$Nodename\`"" | Set-Content c:\TigeraCalico\config.ps1
(cat c:\TigeraCalico\config.ps1) -replace '^\\\$env\:CALICO_DATASTORE_TYPE(.*?)\$',"\`\$env\`:CALICO_DATASTORE_TYPE=\`"\$DatastoreType\`"" | Set-Content c:\TigeraCalico\config.ps1
echo "install Calico"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\install-calico.ps1 -Wait
# Invoke-Command -FilePath \$CalicoDir\\install-calico.ps1
echo "start kubelet"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\kubernetes\\start-kubelet.ps1
echo "start kube-proxy"
Start-Process powershell.exe -ArgumentList \$CalicoDir\\kubernetes\\start-kube-proxy.ps1
echo "ensuring AWS metadata route"
\$MetaRoute='169.254.169.254/32'
\$Route=(Get-NetRoute -DestinationPrefix \$MetaRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if (\$Route){
  echo "AWS metadata route '\$MetaRoute' exists"
}else{
  echo "AWS metadata route is missing. Adding the routes '\$MetaRoute'"
  echo "note, the command looks for a specific network adapter naming. Adjust the query if needed."
  New-NetRoute -DestinationPrefix \$MetaRoute -InterfaceIndex (Get-NetAdapter | where {\$_.Name -like "*(ethernet 2)*"} | select -ExpandProperty ifIndex)
}
EOF
