# ── 사용자 접근 URL ──────────────────────────────────────
output "frontend_url" {
  description = "프론트엔드 진입점 (CloudFront)"
  value       = "https://${module.cdn.frontend_url}"
}

output "api_url" {
  description = "백엔드 API 베이스 (CloudFront /api/v1 path)"
  value       = "https://${module.cdn.frontend_url}/api/v1"
}

output "alb_dns_name" {
  description = "ALB 직접 DNS (디버그용 — 일반 사용자에게는 노출하지 마세요)"
  value       = module.alb.alb_dns_name
}

# ── ECR (CI 가 push 할 곳) ───────────────────────────────
output "ecr_api_repo" {
  description = "백엔드(FastAPI) ECR 레포 URI"
  value       = module.ecr.api_repo_url
}

output "ecr_frontend_repo" {
  description = "프론트엔드(Next.js) ECR 레포 URI"
  value       = module.ecr.frontend_repo_url
}

# ── 시크릿 ARN (값은 절대 출력하지 않음) ────────────────
output "secret_app_arn" {
  description = "런타임 시크릿 (NVD/GitHub/Anthropic) ARN — 콘솔에서 값 채우세요"
  value       = module.secrets.app_secret_arn
}

output "secret_db_arn" {
  description = "DB 마스터 자격 ARN"
  value       = module.secrets.db_master_secret_arn
}

output "secret_database_url_arn" {
  description = "백엔드가 주입받는 DATABASE_URL ARN"
  value       = module.secrets.database_url_secret_arn
}

# ── DB ──────────────────────────────────────────────────
output "db_endpoint" {
  description = "RDS endpoint"
  value       = module.db.endpoint
}

# ── 네트워크 (디버그) ──────────────────────────────────
output "vpc_id"             { value = module.network.vpc_id }
output "private_subnet_ids" { value = module.network.private_subnet_ids }
