output "frontend_url" {
  description = "프론트엔드 진입 도메인 (자체 도메인 있으면 그것, 없으면 CloudFront 기본)"
  value       = var.domain_name != "" ? var.domain_name : aws_cloudfront_distribution.this.domain_name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.this.id
}
