# FastAPI — Fargate Spot, ALB target.
# alembic 마이그레이션은 컨테이너 entrypoint 에서 자동 실행 (현 backend/Dockerfile 그대로).

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.name_prefix}-api"
  retention_in_days = 14
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name_prefix}-api"
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = var.task_exec_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([{
    name      = "api"
    image     = var.image
    essential = true
    # entrypoint 에서 alembic 자동 실행. 첫 배포 후 task 가 multiple-replicate 되면
    # alembic 의 advisory lock 으로 동시 실행 방지 — 첫 컨테이너만 마이그레이션 적용,
    # 이후 컨테이너는 lock 대기 후 noop.
    command = [
      "sh", "-c",
      "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"
    ]
    portMappings = [{
      name          = "api"
      containerPort = 8000
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "REDIS_URL",                value = var.redis_url },
      { name = "MEILI_HOST",               value = var.meili_host },
      { name = "CORS_ORIGINS",             value = var.cors_origins_json },
      { name = "KESTREL_RUN_SCHEDULER",    value = "false" }, # scheduler 는 별도 service
      { name = "INSTALL_CLAUDE_CLI",       value = "1" },
      { name = "CLAUDE_HOME",              value = "/home/app" }
    ]
    secrets = [
      { name = "DATABASE_URL",       valueFrom = var.database_url_secret_arn },
      { name = "NVD_API_KEY",        valueFrom = "${var.app_secret_arn}:NVD_API_KEY::" },
      { name = "GITHUB_TOKEN",       valueFrom = "${var.app_secret_arn}:GITHUB_TOKEN::" },
      { name = "ANTHROPIC_API_KEY",  valueFrom = "${var.app_secret_arn}:ANTHROPIC_API_KEY::" },
      { name = "MEILI_MASTER_KEY",   valueFrom = "${var.app_secret_arn}:MEILI_MASTER_KEY::" },
      { name = "SENTRY_DSN",         valueFrom = "${var.app_secret_arn}:SENTRY_DSN::" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.api.name
        awslogs-region        = data.aws_region.current.name
        awslogs-stream-prefix = "ecs"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "curl -sf http://localhost:8000/api/v1/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])
}

# Namespace 는 cache 모듈이 생성. 여기서는 조회만.
data "aws_service_discovery_http_namespace" "this" {
  name = "${var.name_prefix}.internal"
}

resource "aws_ecs_service" "api" {
  name            = "${var.name_prefix}-api"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count

  capacity_provider_strategy {
    capacity_provider = "FARGATE_SPOT"
    weight            = 4
    base              = 0
  }
  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1 # 최소 1개는 안정적인 on-demand 로
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_tasks_sg_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.alb_target_group_arn
    container_name   = "api"
    container_port   = 8000
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
    ignore_changes = [task_definition] # CI 가 update-service 로 갈아끼움
  }
}

# ── Autoscaling ─────────────────────────────────────────
resource "aws_appautoscaling_target" "api" {
  max_capacity       = 4
  min_capacity       = var.desired_count
  resource_id        = "service/${split("/", var.cluster_arn)[1]}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "${var.name_prefix}-api-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 60
    scale_out_cooldown = 30
  }
}

data "aws_region" "current" {}
