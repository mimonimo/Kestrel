# RDS PostgreSQL 16 — db.t4g.micro (Free Tier 12개월)
# 추후 부하 증가 시 Aurora Serverless v2 마이그레이션 패스 있음 (snapshot → restore).

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name_prefix}-pg16"
  family = "postgres16"

  # tsvector + GIN 인덱스 그대로 사용 — 기본값으로 충분.
  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # 1초 이상 쿼리만 로깅
  }
}

resource "aws_db_instance" "this" {
  identifier              = "${var.name_prefix}-pg"
  engine                  = "postgres"
  engine_version          = "16.4"
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage
  max_allocated_storage   = 100      # autoscale 상한
  storage_type            = "gp3"
  storage_encrypted       = true

  db_name                 = var.db_name
  username                = var.db_master_username
  password                = var.db_master_password

  db_subnet_group_name    = aws_db_subnet_group.this.name
  vpc_security_group_ids  = [var.db_sg_id]
  parameter_group_name    = aws_db_parameter_group.this.name

  multi_az                = var.env == "prod" ? false : false # Free Tier 유지. prod 안정화 시 true.
  publicly_accessible     = false

  backup_retention_period = 7
  backup_window           = "17:00-18:00"  # KST 02-03
  maintenance_window      = "Mon:18:00-Mon:19:00"

  skip_final_snapshot     = var.env != "prod"
  deletion_protection     = var.env == "prod"
  apply_immediately       = false

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = { Name = "${var.name_prefix}-pg" }
}

# DATABASE_URL 자동 채움 — secrets 모듈에서 만든 빈 secret 을 endpoint 가 정해진 뒤 갱신
resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = data.aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql+asyncpg://${var.db_master_username}:${var.db_master_password}@${aws_db_instance.this.endpoint}/${var.db_name}"
}

data "aws_secretsmanager_secret" "database_url" {
  name = "${var.name_prefix}/app/database-url"
}
