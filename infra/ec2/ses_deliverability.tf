###############################################################################
# Kestrel — SES 전달성(deliverability) 구성. 운영 중 콘솔로 적용한 것을 IaC 로
# 역코드화(라이브 기준). 프로덕션 액세스 승격 후 도메인 정렬 기반 전달성 확보:
#
#   - 커스텀 MAIL FROM(mail.<domain>) → Return-Path 를 서비스 도메인으로 정렬.
#     이걸 켜면 AWS 가 요구하는 (1) 피드백 MX, (2) SPF TXT 를 직접 생성해야 한다.
#   - SPF(mail.<domain> TXT) → amazonses.com 발신 서버 인가.
#   - DMARC(_dmarc.<domain> TXT) → 정렬 결과 모니터링(현재 p=none 관측 단계).
#
# 도메인이 설정된 경우에만 구성(nip.io 모드는 메일 비활성). main.tf 의
# aws_ses_domain_identity / _dkim / ses_send IAM 정책과 짝을 이룬다.
#
# 참고: SES "프로덕션 액세스 승격" 과 "계정 억제 목록(BOUNCE/COMPLAINT)" 은
# 계정 레벨 설정/서포트 요청이라 이 스택의 Terraform 리소스로 표현되지 않는다
# (라이브: ProductionAccessEnabled=true, SendingEnabled=true, 억제=BOUNCE/COMPLAINT).
###############################################################################

# ── 커스텀 MAIL FROM 도메인 ──────────────────────────────────
resource "aws_ses_domain_mail_from" "this" {
  count            = var.domain_name == "" ? 0 : 1
  domain           = aws_ses_domain_identity.this[0].domain
  mail_from_domain = "mail.${var.domain_name}"
  # MX 조회 실패 시 SES 기본 도메인으로 폴백(발송 자체는 계속). 라이브와 일치.
  behavior_on_mx_failure = "UseDefaultValue"
}

# ── MAIL FROM 용 피드백 MX ───────────────────────────────────
# 바운스/컴플레인 피드백을 SES 리전 피드백 엔드포인트로 받는다.
resource "aws_route53_record" "mail_from_mx" {
  count   = var.domain_name == "" ? 0 : 1
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = aws_ses_domain_mail_from.this[0].mail_from_domain
  type    = "MX"
  ttl     = 1800
  records = ["10 feedback-smtp.${var.aws_region}.amazonses.com"]
}

# ── MAIL FROM 용 SPF ─────────────────────────────────────────
resource "aws_route53_record" "mail_from_spf" {
  count   = var.domain_name == "" ? 0 : 1
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = aws_ses_domain_mail_from.this[0].mail_from_domain
  type    = "TXT"
  ttl     = 1800
  records = ["v=spf1 include:amazonses.com ~all"]
}

# ── DMARC — 정렬 모니터링(p=none) ────────────────────────────
# 리포트를 관찰한 뒤 quarantine/reject 로 강화할 여지가 있다(라이브: p=none).
resource "aws_route53_record" "dmarc" {
  count   = var.domain_name == "" ? 0 : 1
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 1800
  records = ["v=DMARC1; p=none;"]
}
