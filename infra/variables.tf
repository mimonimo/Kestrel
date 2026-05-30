# ─────────────────────────── 기본 ───────────────────────────
variable "project" {
  description = "프로젝트 이름 (모든 리소스 이름 prefix)"
  type        = string
  default     = "kestrel"
}

variable "env" {
  description = "환경 이름 (dev / prod 등)"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "리전"
  type        = string
  default     = "ap-northeast-2" # 서울
}

# ─────────────────────────── 네트워크 ──────────────────────
variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "az_count" {
  description = "사용할 가용영역 수 (DB Multi-AZ 위해 최소 2)"
  type        = number
  default     = 2
}

# ─────────────────────────── DB ────────────────────────────
variable "db_name" {
  type    = string
  default = "kestrel"
}

variable "db_master_username" {
  type    = string
  default = "kestrel_admin"
}

variable "db_instance_class" {
  description = "RDS 인스턴스 클래스 (t4g.micro = Free Tier)"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "초기 스토리지 GB (gp3, 자동 확장)"
  type        = number
  default     = 20
}

# ─────────────────────────── 도메인 (옵션) ────────────────
variable "domain_name" {
  description = "자체 도메인. 비워두면 CloudFront 기본 도메인만 사용."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "기존 Route53 hosted zone ID (자체 도메인 사용 시)"
  type        = string
  default     = ""
}

# ─────────────────────────── ECS 사이징 ───────────────────
# Fargate Spot 사용 — 일시적 중단 가능하지만 70% 저렴.
# scheduler 만 on-demand 유지 (단일 인스턴스 보장).
variable "api_desired_count"      { default = 1 }
variable "api_cpu"                { default = 512 }   # 0.5 vCPU
variable "api_memory"             { default = 1024 }  # 1 GB

variable "frontend_desired_count" { default = 1 }
variable "frontend_cpu"           { default = 256 }
variable "frontend_memory"        { default = 512 }

variable "scheduler_cpu"          { default = 256 }
variable "scheduler_memory"       { default = 512 }

variable "redis_cpu"              { default = 256 }
variable "redis_memory"           { default = 512 }

variable "meili_cpu"              { default = 512 }
variable "meili_memory"           { default = 1024 }

# ─────────────────────────── 컨테이너 이미지 태그 ─────────
# CI 가 ECR 에 push 한 태그를 가리키도록. 초기엔 "latest" 로 시작하고,
# 운영 단계에선 git SHA 로 변경 권장.
variable "image_tag_api"       { default = "latest" }
variable "image_tag_frontend"  { default = "latest" }
variable "image_tag_scheduler" { default = "latest" }
