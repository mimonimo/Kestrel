# 최소 알람 — 비용 거의 0.
# SNS 토픽만 만들어 두고 이메일 구독은 콘솔에서 직접. (Terraform 으로 만들면
# 이메일 confirm 링크 누를 때까지 apply 가 미완료 상태로 남음.)

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

# 한 곳에서 다 보게 통합 로그 그룹 정책 — 각 서비스 모듈이 만든 로그 그룹은 이미 retention 14일.
# 여기서는 별도로 budget alert 만 추가 (월 비용 임계 초과 시 알림).

resource "aws_budgets_budget" "monthly" {
  name              = "${var.name_prefix}-monthly"
  budget_type       = "COST"
  limit_amount      = "150"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2026-01-01_00:00"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_sns_topic_arns  = [aws_sns_topic.alerts.arn]
  }
}
