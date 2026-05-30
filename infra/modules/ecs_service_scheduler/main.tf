# APScheduler — 동일 backend 이미지를 KESTREL_RUN_SCHEDULER=true 로 띄움.
# desired_count = 1 + on-demand (Spot 회피) — 단일 인스턴스 보장.
# 같은 백엔드 코드를 사용하므로 ECR 레포는 api 와 동일.

resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/ecs/${var.name_prefix}-scheduler"
  retention_in_days = 14
}

resource "aws_ecs_task_definition" "scheduler" {
  family                   = "${var.name_prefix}-scheduler"
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = var.task_exec_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([{
    name      = "scheduler"
    image     = var.image
    essential = true
    # 기본 entrypoint(uvicorn) 대신 scheduler 전용 entrypoint —
    # backend 코드에서 KESTREL_RUN_SCHEDULER 만 켜면 uvicorn 도 같이 뜨지만
    # 이 task 는 API 트래픽 안 받으므로 listen 만 하고 놀게 둠 (heartbeat 용).
    environment = [
      { name = "REDIS_URL",             value = var.redis_url },
      { name = "MEILI_HOST",            value = var.meili_host },
      { name = "KESTREL_RUN_SCHEDULER", value = "true" },
      { name = "KESTREL_API_DISABLED",  value = "false" }, # 헬스체크용 8000 listen 유지
      { name = "INSTALL_CLAUDE_CLI",    value = "0" },     # scheduler 는 AI 호출 안 함
    ]
    secrets = [
      { name = "DATABASE_URL",       valueFrom = var.database_url_secret_arn },
      { name = "NVD_API_KEY",        valueFrom = "${var.app_secret_arn}:NVD_API_KEY::" },
      { name = "GITHUB_TOKEN",       valueFrom = "${var.app_secret_arn}:GITHUB_TOKEN::" },
      { name = "MEILI_MASTER_KEY",   valueFrom = "${var.app_secret_arn}:MEILI_MASTER_KEY::" },
      { name = "SENTRY_DSN",         valueFrom = "${var.app_secret_arn}:SENTRY_DSN::" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.scheduler.name
        awslogs-region        = data.aws_region.current.name
        awslogs-stream-prefix = "ecs"
      }
    }
  }])
}

data "aws_service_discovery_http_namespace" "this" {
  name = "${var.name_prefix}.internal"
}

resource "aws_ecs_service" "scheduler" {
  name            = "${var.name_prefix}-scheduler"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.scheduler.arn
  desired_count   = 1
  launch_type     = "FARGATE" # on-demand — 중복 실행 방지

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_tasks_sg_id]
    assign_public_ip = false
  }

  service_connect_configuration {
    enabled   = true
    namespace = data.aws_service_discovery_http_namespace.this.arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [task_definition]
  }
}

data "aws_region" "current" {}
