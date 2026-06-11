###############################################################################
# Kestrel — AWS 네이티브 에러 추적 (CloudWatch Logs → 메트릭필터 → 알람 → SNS).
#
# 흐름:
#   - 박스의 docker daemon 이 모든 컨테이너 로그를 이 로그그룹으로 전송
#     (/etc/docker/daemon.json 의 log-driver=awslogs — user_data.sh.tpl 참조).
#   - 메트릭 필터가 ERROR/CRITICAL/Traceback 라인을 카운트 → 커스텀 지표.
#   - 알람이 5분 내 1건 이상이면 SNS 토픽으로 → 이메일 통지.
#
# 비용: 저트래픽 기준 로그 수집 수십 MB/월(몇 센트) + 알람 $0.10/월 수준.
###############################################################################

# 알람 통지를 받을 이메일 (구독 후 확인 메일의 링크 클릭 필요).
variable "alert_email" {
  type        = string
  default     = "y202437030@ync.ac.kr"
  description = "CloudWatch 에러 알람을 받을 이메일 주소"
}

# ── 컨테이너 로그 그룹 ────────────────────────────────────────
resource "aws_cloudwatch_log_group" "containers" {
  name              = "/kestrel/${var.env}/containers"
  retention_in_days = 14
  tags              = { Name = "${local.name_prefix}-logs" }
}

# 인스턴스 호스트 역할에 로그 전송 권한 부여(awslogs 드라이버가 인스턴스
# 역할 자격증명을 사용 — 정적 키 불필요).
resource "aws_iam_role_policy" "cw_logs" {
  name = "${local.name_prefix}-cw-logs"
  role = aws_iam_role.host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
      ]
      Resource = [
        aws_cloudwatch_log_group.containers.arn,
        "${aws_cloudwatch_log_group.containers.arn}:*",
      ]
    }]
  })
}

# ── SNS 토픽 + 이메일 구독 ────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── 에러 메트릭 필터 ──────────────────────────────────────────
# 비정형(plain text) 로그에서 강한 에러 신호(미처리 예외 Traceback,
# CRITICAL/ERROR 레벨)를 OR 매칭해 카운트. 노이즈가 많으면 알람 임계치를
# 올리거나 패턴을 좁히면 된다.
resource "aws_cloudwatch_log_metric_filter" "app_errors" {
  name           = "${local.name_prefix}-app-errors"
  log_group_name = aws_cloudwatch_log_group.containers.name
  pattern        = "?\"Traceback (most recent call last)\" ?\"CRITICAL\" ?\"ERROR\""

  metric_transformation {
    name          = "AppErrors"
    namespace     = "Kestrel/${var.env}"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# ── 에러 알람 → SNS ──────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "app_errors" {
  alarm_name          = "${local.name_prefix}-app-errors"
  alarm_description   = "Kestrel 컨테이너 로그에서 에러(Traceback/ERROR/CRITICAL) 발생"
  namespace           = "Kestrel/${var.env}"
  metric_name         = "AppErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# 편의 출력.
output "alerts_sns_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "에러 알람 SNS 토픽 ARN"
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.containers.name
  description = "컨테이너 로그 그룹 이름"
}
