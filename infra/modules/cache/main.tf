# Redis 7 OSS on Fargate (Spot) + EFS (AOF 영속).
# ElastiCache Serverless 최소 ~$50/월 대비 약 $4/월. 트래픽 적은 단계에선 압도적.
# Service Connect (이름 = "redis") 로 다른 task 에서 "redis:6379" 로 접근.

# ── EFS — Redis dump 영속화 ─────────────────────────────
resource "aws_efs_file_system" "redis" {
  creation_token   = "${var.name_prefix}-redis-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"   # 트래픽 적은 단계엔 bursting 무료
  encrypted        = true
  tags = { Name = "${var.name_prefix}-redis-efs" }

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_mount_target" "redis" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.redis.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [var.efs_sg_id]
}

# ── CloudWatch log group ───────────────────────────────
resource "aws_cloudwatch_log_group" "redis" {
  name              = "/ecs/${var.name_prefix}-redis"
  retention_in_days = 14
}

# ── Service Discovery (Service Connect 용 namespace) ──
resource "aws_service_discovery_http_namespace" "this" {
  name = "${var.name_prefix}.internal"
}

# ── Task definition ────────────────────────────────────
resource "aws_ecs_task_definition" "redis" {
  family                   = "${var.name_prefix}-redis"
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = var.task_exec_role_arn
  task_role_arn            = var.task_role_arn

  volume {
    name = "redis-data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.redis.id
      transit_encryption = "ENABLED"
    }
  }

  container_definitions = jsonencode([{
    name      = "redis"
    image     = "public.ecr.aws/docker/library/redis:7.4-alpine"
    essential = true
    command   = ["redis-server", "--appendonly", "yes", "--dir", "/data"]
    portMappings = [{
      name          = "redis"
      containerPort = 6379
      protocol      = "tcp"
      appProtocol   = "tcp"
    }]
    mountPoints = [{
      containerPath = "/data"
      sourceVolume  = "redis-data"
      readOnly      = false
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.redis.name
        awslogs-region        = data.aws_region.current.name
        awslogs-stream-prefix = "ecs"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "redis-cli ping || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 10
    }
  }])
}

resource "aws_ecs_service" "redis" {
  name            = "${var.name_prefix}-redis"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.redis.arn
  desired_count   = 1
  launch_type     = "FARGATE" # Spot 시 재시작 빈도 ↑ 우려, on-demand 유지 (작아서 비용 미미)

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.redis_sg_id]
    assign_public_ip = false
  }

  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.this.arn
    service {
      port_name      = "redis"
      discovery_name = "redis"
      client_alias {
        port     = 6379
        dns_name = "redis"
      }
    }
  }

  depends_on = [aws_efs_mount_target.redis]
}

data "aws_region" "current" {}
