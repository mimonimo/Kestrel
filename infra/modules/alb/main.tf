# ALB — public subnet 에 위치, SG 가 CloudFront prefix list 만 허용.
# Listener 는 HTTP 80 만 — TLS 종료는 CloudFront 에서 수행 (origin protocol = HTTP).
# 경로 기반 라우팅:
#   /api/*  → API target group (port 8000)
#   default → Frontend target group (port 3000)

resource "aws_lb" "this" {
  name               = "${var.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = var.public_subnet_ids
  security_groups    = [var.alb_sg_id]

  enable_deletion_protection = false
  idle_timeout               = 60
}

# ── API target group ───────────────────────────────────
resource "aws_lb_target_group" "api" {
  name        = "${var.name_prefix}-tg-api"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    path                = "/api/v1/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200-299"
  }

  deregistration_delay = 30
}

# ── Frontend target group ──────────────────────────────
resource "aws_lb_target_group" "frontend" {
  name        = "${var.name_prefix}-tg-frontend"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200-399"
  }

  deregistration_delay = 30
}

# ── Listener (HTTP 80, CloudFront 가 origin 호출) ─────
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  condition {
    path_pattern {
      values = ["/api/*", "/docs", "/openapi.json"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
