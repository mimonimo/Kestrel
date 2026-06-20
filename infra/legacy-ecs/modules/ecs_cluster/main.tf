# ECS Cluster + Fargate capacity providers (Spot 우선)
# IAM: task execution role (ECR pull, log push, secret fetch),
#      task role (런타임 권한 — 거의 없음. 필요해지면 확장)

resource "aws_ecs_cluster" "this" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Fargate Spot 우선, On-Demand 는 Spot 부족 시 fallback
resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE_SPOT"
    weight            = 4
    base              = 0
  }
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 0
  }
}

# ── Task Execution Role ─────────────────────────────────
# ECS agent 가 ECR pull + CloudWatch log push + Secrets Manager fetch 할 때 사용.
data "aws_iam_policy_document" "task_exec_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_exec" {
  name               = "${var.name_prefix}-task-exec"
  assume_role_policy = data.aws_iam_policy_document.task_exec_assume.json
}

resource "aws_iam_role_policy_attachment" "task_exec_managed" {
  role       = aws_iam_role.task_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Secrets Manager 권한 — 우리 시크릿만 접근.
resource "aws_iam_role_policy" "task_exec_secrets" {
  name = "${var.name_prefix}-task-exec-secrets"
  role = aws_iam_role.task_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ]
      Resource = [
        var.app_secret_arn,
        var.db_secret_arn,
        # database_url secret 은 secrets 모듈에서 생성 — 이름으로 매칭
        "arn:aws:secretsmanager:*:*:secret:${var.name_prefix}/app/database-url-*"
      ]
    }]
  })
}

# ── Task Role (런타임 권한) ────────────────────────────
# 현재 백엔드/프런트엔드는 AWS API 직접 호출 X (DB/Redis/Meili 만 사용).
# 미래에 S3 업로드, SES 메일, SNS 알림 등 추가하면 여기 정책 붙이세요.
resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.task_exec_assume.json
}
