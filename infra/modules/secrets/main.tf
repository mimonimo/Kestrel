resource "random_password" "db_master" {
  length           = 32
  special          = true
  override_special = "!#%^*-_=+"
}

resource "aws_secretsmanager_secret" "db_master" {
  name                    = "${var.name_prefix}/db/master"
  description             = "RDS master credentials"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username = var.db_master_username
    password = random_password.db_master.result
  })
}

# 백엔드 task 에 직접 주입할 DATABASE_URL (편의용)
# RDS endpoint 는 모듈 간 의존성을 단순화하기 위해 변수 대신 추후 채움 — null_resource 로 갱신.
# 여기서는 형식만 잡아두고, db 모듈 outputs 으로 만들어진 endpoint 를 ecs 모듈이 환경변수로 받아 조립합니다.
resource "aws_secretsmanager_secret" "database_url" {
  name        = "${var.name_prefix}/app/database-url"
  description = "DATABASE_URL — db 모듈 outputs 에서 자동 생성 (수동 변경 금지)"
}

resource "random_password" "meili_master" {
  length  = 48
  special = false
}

# JWT 서명용 secret — 64자 무작위. Terraform 이 한 번 생성한 뒤로는
# 이그노어. 로테이션 필요 시 ``terraform taint random_password.jwt_secret``
# 후 apply (전 사용자 강제 재로그인).
resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

# 운영자가 콘솔/CLI 로 채워야 할 외부 API 토큰들.
# 초기엔 빈 값으로 만들고, 이후 값 갱신은 ignore_changes 로 보호.
resource "aws_secretsmanager_secret" "app" {
  name = "${var.name_prefix}/app/runtime"
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    NVD_API_KEY           = ""
    GITHUB_TOKEN          = ""
    ANTHROPIC_API_KEY     = ""
    MEILI_MASTER_KEY      = random_password.meili_master.result
    SENTRY_DSN            = ""
    JWT_SECRET            = random_password.jwt_secret.result
    INITIAL_ADMIN_EMAILS  = ""
  })
  lifecycle {
    ignore_changes = [secret_string]
  }
}
