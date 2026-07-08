###############################################################################
# Kestrel — 가용성(다운) 감시. 기존 알람은 전부 *로그 기반*(cloudwatch.tf 의
# AppErrors)이라 인스턴스/Caddy 가 통째로 죽어 로그가 끊기면 오히려 침묵한다
# (treat_missing_data=notBreaching). 이 파일이 그 공백을 메운다:
#
#   1) Route53 Health Check — 외부에서 https://www.<domain>/api/v1/health 를
#      30초 간격으로 실측(Caddy → backend 경유라 프록시·앱 다운 모두 감지).
#      비용 ~$0.50/월.
#   2) HealthCheckStatus 알람 — 지표가 us-east-1 에만 발행되므로 알람·SNS 도
#      us-east-1 (providers.tf 의 aws.use1). 이메일 구독은 확인 클릭 필요.
#   3) EC2 StatusCheckFailed 알람 — 하드웨어/OS 수준 장애. 서울 리전이라
#      기존 kestrel-prod-alerts 토픽 재사용.
#
# 도메인이 설정된 경우에만 (1)(2) 생성 — nip.io 모드에선 EC2 알람만.
###############################################################################

# ── 1) Route53 Health Check (외부 관측) ──────────────────────
resource "aws_route53_health_check" "www" {
  count             = var.domain_name == "" ? 0 : 1
  fqdn              = "www.${var.domain_name}"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/api/v1/health"
  request_interval  = 30 # 표준 간격(빠른 10초는 추가 요금)
  failure_threshold = 3  # 연속 3회(~90초) 실패 시 unhealthy

  tags = { Name = "${local.name_prefix}-www-health" }
}

# ── 2) us-east-1 SNS + 다운 알람 ─────────────────────────────
# 알람 액션은 알람과 같은 리전의 토픽만 가능 → 서울 토픽 재사용 불가.
resource "aws_sns_topic" "alerts_use1" {
  count    = var.domain_name == "" ? 0 : 1
  provider = aws.use1
  name     = "${local.name_prefix}-alerts-use1"
}

resource "aws_sns_topic_subscription" "alerts_use1_email" {
  count     = var.domain_name == "" ? 0 : 1
  provider  = aws.use1
  topic_arn = aws_sns_topic.alerts_use1[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "site_down" {
  count             = var.domain_name == "" ? 0 : 1
  provider          = aws.use1
  alarm_name        = "${local.name_prefix}-site-down"
  alarm_description = "Kestrel: www.${var.domain_name} 헬스체크 실패(사이트 다운). Caddy/백엔드/인스턴스 확인."
  namespace         = "AWS/Route53"
  metric_name       = "HealthCheckStatus"
  dimensions = {
    HealthCheckId = aws_route53_health_check.www[0].id
  }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  # 헬스체크 지표 자체가 끊긴 것도 이상 신호 → breaching.
  treat_missing_data = "breaching"
  alarm_actions      = [aws_sns_topic.alerts_use1[0].arn]
  # 복구 통지도 받는다 — 다운 알람은 복구 시점을 아는 게 중요.
  ok_actions = [aws_sns_topic.alerts_use1[0].arn]
}

# ── 3) EC2 상태 검사 알람 (서울, 기존 토픽) ──────────────────
# 시스템(하이퍼바이저)·인스턴스(OS) 검사 실패 통합 지표. 인스턴스를 의도적으로
# 중지한 경우 지표가 사라지는데, 그건 다운 알람(위)이 잡으므로 notBreaching.
resource "aws_cloudwatch_metric_alarm" "ec2_status_check" {
  alarm_name        = "${local.name_prefix}-ec2-status-check"
  alarm_description = "Kestrel: EC2 상태 검사 실패(하드웨어/OS 수준). 재부팅·복구 필요할 수 있음."
  namespace         = "AWS/EC2"
  metric_name       = "StatusCheckFailed"
  dimensions = {
    InstanceId = aws_instance.host.id
  }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

output "health_check_id" {
  value       = var.domain_name == "" ? "" : aws_route53_health_check.www[0].id
  description = "Route53 헬스체크 ID (지표는 us-east-1 CloudWatch)"
}
