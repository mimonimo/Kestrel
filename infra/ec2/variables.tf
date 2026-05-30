variable "env" {
  type        = string
  default     = "prod"
  description = "환경 이름 — 리소스명 접두사로 사용"
}

variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

# 인스턴스 사양 — t4g.small (2 vCPU 2 GB ARM). 첫 해 Free Tier (750h/월) 적용 가능.
variable "instance_type" {
  type    = string
  default = "t4g.small"
}

# 데이터 EBS — Postgres / Docker volumes / mitre repo 등 모두 여기에 저장.
# 인스턴스 교체해도 detach → attach 로 데이터 유지.
variable "data_volume_size_gb" {
  type    = number
  default = 30
}

# 운영자 IP — SSH 가 필요할 때만 사용. 평소는 SSM Session Manager 사용 권장.
# 비워두면 SSH 포트 자체를 열지 않음 (SSM 만 사용).
variable "ssh_allowed_cidr" {
  type    = string
  default = ""
}

# 도메인 — 비우면 EIP 의 ``<ip>.nip.io`` 로 동작 (Let's Encrypt 자동 발급).
# 본인 도메인 있으면 Route53 또는 다른 DNS 에서 A 레코드를 EIP 로 향하게 한 뒤 여기에 채움.
variable "domain_name" {
  type    = string
  default = ""
}

# Caddy 가 Let's Encrypt 발급 시 ACME 등록에 사용할 이메일.
variable "tls_email" {
  type    = string
  default = "y202437030@ync.ac.kr"
}

# Kestrel 의 부트스트랩 admin 이메일 (회원가입 시 자동 admin 부여).
variable "initial_admin_emails" {
  type    = string
  default = "y202437030@ync.ac.kr"
}

# Git repo — user_data 가 clone 해 docker compose up.
variable "git_repo_url" {
  type    = string
  default = "https://github.com/mimonimo/Kestrel.git"
}

variable "git_branch" {
  type    = string
  default = "main"
}
