# Meilisearch on Fargate + EFS (인덱스 영속).
# OpenSearch Service 대비 1/8 비용. 단일 노드 — PG tsvector fallback 코드가 이미 있어 실패 시 검색은 살아남음.

resource "aws_efs_file_system" "meili" {
  creation_token   = "${var.name_prefix}-meili-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  encrypted        = true
  tags = { Name = "${var.name_prefix}-meili-efs" }

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_mount_target" "meili" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.meili.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [var.efs_sg_id]
}

resource "aws_cloudwatch_log_group" "meili" {
  name              = "/ecs/${var.name_prefix}-meili"
  retention_in_days = 14
}

# Meilisearch 와 Redis 가 같은 Service Connect namespace 를 공유합니다.
# cache 모듈이 namespace 를 만들었으므로 여기서는 ID 만 조회.
data "aws_service_discovery_http_namespace" "this" {
  name = "${var.name_prefix}.internal"

  # cache 모듈 적용 후에야 존재 — depends_on 으로 순서 강제.
  depends_on = []
}

resource "aws_ecs_task_definition" "meili" {
  family                   = "${var.name_prefix}-meili"
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = var.task_exec_role_arn
  task_role_arn            = var.task_role_arn

  volume {
    name = "meili-data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.meili.id
      transit_encryption = "ENABLED"
    }
  }

  container_definitions = jsonencode([{
    name      = "meili"
    image     = "getmeili/meilisearch:v1.10"
    essential = true
    portMappings = [{
      name          = "meili"
      containerPort = 7700
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    mountPoints = [{
      containerPath = "/meili_data"
      sourceVolume  = "meili-data"
      readOnly      = false
    }]
    environment = [
      { name = "MEILI_ENV",     value = "production" },
      { name = "MEILI_NO_ANALYTICS", value = "true" }
    ]
    secrets = [
      { name = "MEILI_MASTER_KEY", valueFrom = "${var.app_secret_arn}:MEILI_MASTER_KEY::" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.meili.name
        awslogs-region        = data.aws_region.current.name
        awslogs-stream-prefix = "ecs"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "wget -q -O- http://localhost:7700/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_ecs_service" "meili" {
  name            = "${var.name_prefix}-meili"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.meili.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.meili_sg_id]
    assign_public_ip = false
  }

  service_connect_configuration {
    enabled   = true
    namespace = data.aws_service_discovery_http_namespace.this.arn
    service {
      port_name      = "meili"
      discovery_name = "meili"
      client_alias {
        port     = 7700
        dns_name = "meili"
      }
    }
  }

  depends_on = [aws_efs_mount_target.meili]
}

data "aws_region" "current" {}
