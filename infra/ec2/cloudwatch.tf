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
# 비정형(plain text) 로그에서 *강한* 에러 신호만 카운트한다.
#   - "Traceback (most recent call last)": 미처리 예외(앱 크래시) — 가장 확실한 신호
#   - "CRITICAL": 치명 로그 레벨
# 일반 "ERROR" 는 접속로그/외부 API 일시 오류 등 노이즈가 많아 제외한다.
resource "aws_cloudwatch_log_metric_filter" "app_errors" {
  name           = "${local.name_prefix}-app-errors"
  log_group_name = aws_cloudwatch_log_group.containers.name
  pattern        = "?\"Traceback (most recent call last)\" ?\"CRITICAL\""

  metric_transformation {
    name          = "AppErrors"
    namespace     = "Kestrel/${var.env}"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# ── 에러 알람 → SNS ──────────────────────────────────────────
# 노이즈 억제: 일시적 단발 에러로는 알람이 울리지 않게 한다.
#   - 5분 구간마다 심각 에러 3건 이상이고(threshold=3),
#   - 그런 구간이 연속 3개(15분) 모두 충족할 때만(datapoints=3/3) 발화.
# 즉 "반복·지속되는 큰 문제"에서만 통지. 복구(OK) 메일은 노이즈라 생략.
resource "aws_cloudwatch_metric_alarm" "app_errors" {
  alarm_name          = "${local.name_prefix}-app-errors"
  alarm_description   = "Kestrel: 심각 에러(Traceback/CRITICAL)가 15분(5분×3구간) 연속 다발"
  namespace           = "Kestrel/${var.env}"
  metric_name         = "AppErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ── SES 평판 알람 (반송률 / 불만율) ─────────────────────────
# 운영 중 콘솔로 추가한 것을 IaC 로 역코드화(라이브 기준). SES 는 반송률·불만율이
# 임계치를 넘으면 발송을 정지시키므로, 그 전에 조기 통지한다.
#   - 반송률(BounceRate) ≥ 5%  → 정지 위험 구간.
#   - 불만율(ComplaintRate) ≥ 0.1% → 정지 위험 구간.
# AWS/SES 계정 평판 지표는 시간당 갱신되므로 1시간 구간·1회 위반으로 즉시 통지.
# 도메인(메일 발송)이 켜진 경우에만 생성.
resource "aws_cloudwatch_metric_alarm" "ses_bounce_rate" {
  count               = var.domain_name == "" ? 0 : 1
  alarm_name          = "kestrel-ses-bounce-rate"
  alarm_description   = "SES 반송률(Reputation.BounceRate)이 5% 이상. 방치 시 SES 발송정지 위험."
  namespace           = "AWS/SES"
  metric_name         = "Reputation.BounceRate"
  statistic           = "Maximum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0.05
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "ses_complaint_rate" {
  count               = var.domain_name == "" ? 0 : 1
  alarm_name          = "kestrel-ses-complaint-rate"
  alarm_description   = "SES 불만율(Reputation.ComplaintRate)이 0.1% 이상. 방치 시 SES 발송정지 위험."
  namespace           = "AWS/SES"
  metric_name         = "Reputation.ComplaintRate"
  statistic           = "Maximum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0.001
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# 백엔드(신고 기능)가 알림 토픽으로 직접 발행할 수 있게 권한 부여.
resource "aws_iam_role_policy" "sns_publish" {
  name = "${local.name_prefix}-sns-publish"
  role = aws_iam_role.host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = aws_sns_topic.alerts.arn
    }]
  })
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
