output "public_ip" {
  value       = aws_eip.host.public_ip
  description = "고정 공인 IP. 도메인 없이도 https://<ip>.nip.io 로 접속 가능."
}

output "host_url" {
  value = var.domain_name == "" ? "https://${aws_eip.host.public_ip}.nip.io" : "https://${var.domain_name}"
  description = "브라우저로 접속할 주소. 첫 부팅 후 Caddy 가 Let's Encrypt 인증서 발급까지 ~1-2분 대기."
}

output "ssm_session_command" {
  value       = "aws ssm start-session --target ${aws_instance.host.id}"
  description = "ssh 키 없이 안전한 셸 진입. 사용자 머신에서 그대로 복사·실행."
}

output "instance_id" {
  value = aws_instance.host.id
}

output "data_volume_id" {
  value       = aws_ebs_volume.data.id
  description = "데이터 EBS — 모든 영속 데이터 보관."
}
