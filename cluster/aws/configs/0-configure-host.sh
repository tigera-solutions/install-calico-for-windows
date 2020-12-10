#!/usr/bin/env bash

sudo apt-get update && sudo apt-get install -y apt-transport-https curl socat conntrack ipset
sudo hostnamectl set-hostname $(curl -s http://169.254.169.254/latest/meta-data/local-hostname)
sudo sed -i -- 's/\#PermitRootLogin\ yes/PermitRootLogin yes/g' /etc/ssh/sshd_config
sudo sed -i -- 's/\#AllowTcpForwarding\ yes/AllowTcpForwarding\ yes/g' /etc/ssh/sshd_config
# add kubernetes repo
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
# add Docker CE repo
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update -y && sudo apt-get upgrade -y
sudo dpkg --configure -a
# install necessary packages
sudo apt install -y docker-ce docker-ce-cli containerd.io
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
# sudo snap install kubeadm --classic && sudo snap install kubelet --classic && sudo snap install kubectl --classic
sudo usermod -aG docker ubuntu
newgrp docker
# enable docker service
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo systemctl enable docker
sudo systemctl start docker
# enable and start kubelet service
sudo systemctl enable kubelet && sudo systemctl start kubelet
# sudo systemctl enable snap.kubelet.daemon.service && sudo systemctl start snap.kubelet.daemon.service
# enable ecmp routes on Ubuntu 18.04+
echo 'net.ipv4.fib_multipath_hash_policy=1' | sudo tee -a /etc/sysctl.conf
# Docker recommended settings
cat << EOF | sudo tee -a /etc/sysctl.conf
  # SWAP settings
  vm.swappiness=0
  vm.overcommit_memory=1
  net.bridge.bridge-nf-call-ip6tables=1
  net.bridge.bridge-nf-call-iptables=1
  net.ipv4.ip_forward=1
  net.ipv4.tcp_keepalive_time=600
EOF
sudo systemctl reboot