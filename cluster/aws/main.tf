terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
}

# create EC2 KeyPair
resource "tls_private_key" "rsa_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_keypair" {
  key_name   = var.key_name
  public_key = tls_private_key.rsa_key.public_key_openssh
}

resource "local_file" "private_key" {
    content  = tls_private_key.rsa_key.private_key_pem
    filename = "private_key.pem"
    file_permission = "0600"
}

# Create a VPC
resource "aws_vpc" "calico-vpc" {
  cidr_block = var.vpccidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  enable_classiclink   = false
  instance_tenancy     = "default"
  tags = {
    Name = "${var.resource_prefix}vpc"
  }
}

# Create a private subnet to launch our instances into
resource "aws_subnet" "calico-pub-subnet" {
  vpc_id                  = aws_vpc.calico-vpc.id
  cidr_block              = var.publiccidraz1
  availability_zone = var.az1
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.resource_prefix}pub-subnet",
    "kubernetes.io/cluster/kubernetes" = "owned",
    "kubernetes.io/role/elb" = "1"
  }
}

# Create an internet gateway to give our subnet access to the outside world
resource "aws_internet_gateway" "calico-igw" {
  vpc_id = aws_vpc.calico-vpc.id
  tags = {
    Name = "${var.resource_prefix}igw"
  } 
}

// Route Table
resource "aws_route_table" "calico-public-rt" {
  vpc_id = aws_vpc.calico-vpc.id
  tags = {
    Name = "${var.resource_prefix}public-rt"
  }
}

// Routes
resource "aws_route" "externalroute" {
  route_table_id         = aws_route_table.calico-public-rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.calico-igw.id
}

## Route Table Association
resource "aws_route_table_association" "public1associate" {
  subnet_id      = aws_subnet.calico-pub-subnet.id
  route_table_id = aws_route_table.calico-public-rt.id
}

# Our default security group
resource "aws_security_group" "default" {
  name        = "${var.resource_prefix}sg"
  description = "Used in the terraform"
  vpc_id      = aws_vpc.calico-vpc.id

  # SSH, HTTPs, and kube access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 31443
    to_port     = 31443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "all traffic from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["${var.vpccidr}"]
  }

  # RDP port for remote desktop connection
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # WinRM port for remote script execution
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # kubelet port
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["${var.vpccidr}"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

## IAM Role and Policy for k8s Nodes

resource "aws_iam_role" "k8s-access-role" {
  name               = "${var.resource_prefix}k8s-access-role"
  assume_role_policy = file("ec2-role-trust-policy.json")
}

resource "aws_iam_policy" "k8s-master-access-policy" {
  name        = "${var.resource_prefix}k8s-master-access-policy"
  description = "k8s aws controller policy"
  policy      = file("k8s-master-access-policy.json")
}

resource "aws_iam_policy_attachment" "k8s-master-policy-attach" {
  name       = "policy-attach"
  roles      = [aws_iam_role.k8s-access-role.name]
  policy_arn = aws_iam_policy.k8s-master-access-policy.arn
}

resource "aws_iam_instance_profile" "master-instance_profile" {
  name  = "${var.resource_prefix}master-instance_profile"
  role = aws_iam_role.k8s-access-role.name
}

resource "aws_iam_policy" "k8s-worker-access-policy" {
  name        = "${var.resource_prefix}k8s-worker-access-policy"
  description = "k8s aws controller policy"
  policy      = file("k8s-worker-access-policy.json")
}

resource "aws_iam_policy_attachment" "k8s-worker-policy-attach" {
  name       = "policy-attach"
  roles      = [aws_iam_role.k8s-access-role.name]
  policy_arn = aws_iam_policy.k8s-worker-access-policy.arn
}

resource "aws_iam_instance_profile" "worker-instance_profile" {
  name  = "${var.resource_prefix}worker-instance_profile"
  role = aws_iam_role.k8s-access-role.name
}

resource "aws_instance" "master" {
  connection {
    type = "ssh"
    user = "ubuntu"
    host = self.public_ip
    private_key = tls_private_key.rsa_key.private_key_pem
  }
  # count                   = var.master_count
  instance_type           = var.nix_master_size
  iam_instance_profile    = aws_iam_instance_profile.master-instance_profile.name
  source_dest_check       = false 
  ami                     = var.linux_ami[var.aws_region]
  # key_name = var.key_name
  key_name                = aws_key_pair.ec2_keypair.key_name
  vpc_security_group_ids  = [aws_security_group.default.id]
  subnet_id               = aws_subnet.calico-pub-subnet.id
  user_data               = file("${path.module}/configs/0-cloud-init-nix.yaml")

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = var.nix_master_disk_size
    volume_type = "gp2"
  }

  # create setup dir
  provisioner "remote-exec" {
    inline = [
      "mkdir /home/ubuntu/setup"
    ]
  }
  # copy necessary files to the remote host
  provisioner "file" {
    source      = "configs/0-configure-host.sh"
    destination = "/home/ubuntu/setup/0-configure-host.sh"
  }
  provisioner "file" {
    source      = "configs/1-install-calicoctl.sh"
    destination = "/home/ubuntu/setup/1-install-calicoctl.sh"
  }
  provisioner "file" {
    source      = "configs/1-kubeadm-init-config.yaml"
    destination = "/home/ubuntu/setup/1-kubeadm-init-config.yaml"
  }
  provisioner "file" {
    content     = templatefile("configs/1-kubeadm-join-config.yaml", { master_private_ip = self.private_ip, kube_api_port = 6443 })
    destination = "/home/ubuntu/setup/1-kubeadm-join-config.yaml"
  }
  provisioner "file" {
    source      = "configs/2-ebs-storageclass.yaml"
    destination = "/home/ubuntu/setup/2-ebs-storageclass.yaml"
  }
  provisioner "file" {
    source      = "configs/3-manager-nodeport.yaml"
    destination = "/home/ubuntu/setup/3-manager-nodeport.yaml"
  }
  provisioner "file" {
    source      = "configs/3-loadbalancer.yaml"
    destination = "/home/ubuntu/setup/3-loadbalancer.yaml"
  }
  provisioner "file" {
    source      = var.pull_secret_json_path
    destination = "/home/ubuntu/setup/pull-secret.json"
  }
  provisioner "file" {
    source      = var.calico_license_path
    destination = "/home/ubuntu/setup/license.yaml"
  }
  provisioner "file" {
    source      = "configs/0-reboot-host-nix.sh"
    destination = "/home/ubuntu/setup/0-reboot-host-nix.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /home/ubuntu/setup/0-reboot-host-nix.sh",
      "/home/ubuntu/setup/0-reboot-host-nix.sh"
    ]
  }

  tags = {
    Name = "${var.resource_prefix}master",
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

resource "aws_instance" "worker" {
  connection {
    type = "ssh"
    user = "ubuntu"
    host = self.public_ip
    private_key = tls_private_key.rsa_key.private_key_pem
  }
  count                   = var.nix_worker_count
  instance_type           = var.nix_worker_size
  iam_instance_profile    = aws_iam_instance_profile.worker-instance_profile.name
  source_dest_check       = false
  ami                     = var.linux_ami[var.aws_region]
  key_name                = aws_key_pair.ec2_keypair.key_name
  vpc_security_group_ids  = [aws_security_group.default.id]
  subnet_id               = aws_subnet.calico-pub-subnet.id
  # user_data = file("${path.module}/configs/0-configure-host.sh")
  user_data               = file("${path.module}/configs/0-cloud-init-nix.yaml")

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = var.nix_worker_disk_size
    volume_type = "gp2"
  }

  # create setup dir
  provisioner "remote-exec" {
    inline = [
      "mkdir /home/ubuntu/setup"
    ]
  }
  # copy files to the remote host
  provisioner "file" {
    source      = "configs/0-configure-host.sh"
    destination = "/home/ubuntu/setup/0-configure-host.sh"
  }
  # example to modify kubeadm join config before uploading to the worker host
  provisioner "file" {
    content     = templatefile("configs/1-kubeadm-join-config.yaml", { master_private_ip = aws_instance.master.private_ip, kube_api_port = 6443 })
    destination = "/home/ubuntu/setup/1-kubeadm-join-config.yaml"
  }
  provisioner "file" {
    source      = "configs/0-reboot-host-nix.sh"
    destination = "/home/ubuntu/setup/0-reboot-host-nix.sh"
  }
    provisioner "remote-exec" {
    inline = [
      "chmod +x /home/ubuntu/setup/0-reboot-host-nix.sh",
      "/home/ubuntu/setup/0-reboot-host-nix.sh"
    ]
  }

  tags = {
    Name = "${var.resource_prefix}worker-${count.index + 1}",
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

resource "aws_instance" "win-worker-1" {
  connection {
    # requires SSH server WindowsCapability to be installed
    type = "ssh"
    # user = var.win_username
    # password = var.win_password
    user = "administrator"
    password = rsadecrypt(self.password_data,tls_private_key.rsa_key.private_key_pem)
    host = self.public_ip
    private_key = tls_private_key.rsa_key.private_key_pem
  }
  # count                   = var.win_worker_count
  instance_type           = var.win_worker_size
  iam_instance_profile    = aws_iam_instance_profile.worker-instance_profile.name
  source_dest_check       = false 
  ami                     = var.windows_ami[var.aws_region]
  key_name                = aws_key_pair.ec2_keypair.key_name
  vpc_security_group_ids  = [aws_security_group.default.id]
  subnet_id               = aws_subnet.calico-pub-subnet.id
  user_data               = templatefile("configs/0-cloud-init-win.tmpl", { win_username = var.win_username, win_password = var.win_password, ssh_pub_key = aws_key_pair.ec2_keypair.public_key})
  get_password_data       = true

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = var.win_worker_disk_size
    volume_type = "gp2"
  }

  provisioner "file" {
    content      = tls_private_key.rsa_key.private_key_pem
    destination  = "c:/users/administrator/private_key.pem"
  }

  tags = {
    Name = "${var.resource_prefix}win-worker-1",
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}
