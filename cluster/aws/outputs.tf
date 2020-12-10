output "masters-pub-ip" {
  value = aws_instance.master.public_ip
}

output "masters-pvt-ip" {
  value = aws_instance.master.private_ip
}

output "workers-pub-ip" {
  value = aws_instance.worker.*.public_ip
}

output "workers-pvt-ip" {
  value = aws_instance.worker.*.private_ip
}

output "win-worker-1-pub-ip" {
  value = aws_instance.win-worker-1.public_ip
}

output "win-worker-1-pvt-ip" {
  value = aws_instance.win-worker-1.private_ip
}

output "win-admin-password" {
  value = rsadecrypt(aws_instance.win-worker-1.password_data,tls_private_key.rsa_key.private_key_pem)
}
