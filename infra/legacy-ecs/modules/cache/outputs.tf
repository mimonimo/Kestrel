output "redis_url" {
  description = "백엔드 task 에 주입할 REDIS_URL — Service Connect 내부 DNS"
  value       = "redis://redis:6379/0"
}

output "namespace_arn" {
  description = "Service Connect namespace ARN (다른 모듈이 같이 사용)"
  value       = aws_service_discovery_http_namespace.this.arn
}
