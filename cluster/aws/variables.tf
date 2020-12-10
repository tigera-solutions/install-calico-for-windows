variable "key_name" {
  description = "Desired name of AWS key pair"
}

variable "aws_region" {
  description = "AWS region to launch servers."
  default     = "us-west-2"
}

# variable "calico_windows_zip_path" {
#   description = "Path to Calico for Windows zip file"
# }

variable "pull_secret_json_path" {
  description = "Path to Tigera pull secret JSON file"
}

variable "calico_license_path" {
  description = "Path to Calico Enterprise license file"
}

// Availability zones for the region
variable "az1" {
  default = "us-west-2a"
}

variable "az2" {
  default = "us-west-2b"
}

variable "vpccidr" {
  default = "172.16.0.0/16"
}

variable "publiccidraz1" {
  default = "172.16.0.0/24"
}

# Ubuntu 20.04 LTS (x64)
# find desired AMI: https://cloud-images.ubuntu.com/locator/ec2/
variable "linux_ami" {
  default = {
    us-west-2 = "ami-0f38c153936247588"
  }
}

# Windows Server
variable "windows_ami" {
  default = {
    us-west-2 = "ami-00369e47a7f018918" # Win Server 1909
    # us-west-2 = "ami-0dd2028b183137058" # Win Server 2004
  }
}

# variable "master_count" {
#   default = "1"
# }

variable "nix_worker_count" {
  default = "4"
}

# variable "win_worker_count" {
#   default = "2"
# }

variable "nix_master_size" {
  default = "c5.xlarge" # vCPU: 4, RAM: 8G
}

variable "nix_worker_size" {
  default = "m5a.large" # vCPU: 2, RAM: 8G
}

variable "nix_master_disk_size" {
  default = "20"
}

variable "nix_worker_disk_size" {
  default = "30"
}

variable "win_worker_size" {
  default = "m5a.xlarge" # vCPU: 4, RAM: 16G
}

variable "win_worker_disk_size" {
  default = "60"
}

variable "win_username" {
  default = "calicouser"
}

variable "win_password" {
  default = "P@ssw0rd12345"
}

// resource prefix variable
variable "resource_prefix" {
  default = "cali4win-"
}