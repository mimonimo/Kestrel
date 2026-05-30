output "db_master_secret_arn"   { value = aws_secretsmanager_secret.db_master.arn }
output "database_url_secret_arn" { value = aws_secretsmanager_secret.database_url.arn }
output "app_secret_arn"         { value = aws_secretsmanager_secret.app.arn }

output "db_master_password" {
  value     = random_password.db_master.result
  sensitive = true
}

output "meili_master_key" {
  value     = random_password.meili_master.result
  sensitive = true
}
