# Kestrel · 단일 EC2 운영 가이드

ECS Fargate 풀스택 대비 **약 1/8 비용** (월 $10 미만) 으로 같은 데이터 보존을
달성하는 단일 호스트 구성. 사용자 데이터 (CVE 수집 결과, 가입 사용자, 분석
기록) 만 영속화하면 되는 요구에 맞춰 설계.

```
                   Internet
                      │
              ┌───────▼────────┐
              │  Elastic IP    │
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │  EC2 t4g.small │   ← Free Tier 첫 해 무료
              │   Caddy (TLS)  │
              │   ↓ /api/*     │
              │   backend      │
              │   ↓ everything │
              │   frontend     │
              │                │
              │   postgres ──┐ │
              │   redis      │ │   ← Docker volume 들이 모두
              │   meili      │ │      data EBS (/data/docker) 에
              └──────────────┼─┘
                             │
                  ┌──────────▼──────────┐
                  │ EBS gp3 30 GB       │   ← AWS Backup daily snapshot
                  │  /data              │
                  └─────────────────────┘
```

## 비용 (월)

| 항목 | 금액 |
|---|---|
| EC2 t4g.small (Free Tier 첫 해 / 750h) | $0 → $13 |
| EBS gp3 30 GB (data) + 8 GB (root) | $3 |
| Elastic IP (인스턴스에 attach 된 동안) | $0 |
| AWS Backup snapshot (~30 GB × 7일) | <$1 |
| Data transfer out (월 1 GB) | ~$0 |
| **첫 해 합계** | **~$4/월** |
| **이후 합계** | **~$17/월** |

## 단계별 진행

### 0) 사전 준비 (한 번만)
```bash
# macOS
brew install awscli terraform
```

### 1) AWS 자격증명 등록
AWS Console → IAM → Users → `kestrel-tf-deploy` 생성, `AdministratorAccess`
임시 부여 (배포 후 정책 좁힐 수 있음). Access Key 발급.

```bash
aws configure --profile kestrel-deploy
# Access Key / Secret / region=ap-northeast-2

export AWS_PROFILE=kestrel-deploy
aws sts get-caller-identity  # 계정 ID 확인
```

### 2) (선택) 도메인 구매

**Route53 에서 직접 구매 — 가장 단순.**

AWS Console → Route 53 → Registered domains → Register domain
- `.com` (~$14/년), `.dev` (~$12/년), `.io` (~$39/년) 등
- WHOIS privacy 자동 활성
- 결제 후 5–15분 대기 → "Registered domains" 에 표시되면 완료
- 같은 시점에 hosted zone 도 자동 생성됨 (Terraform 이 자동 lookup)

**외부에서 구매한 경우** (가비아 등):
1. 외부에서 .com 구매
2. AWS Route 53 → Hosted zones → Create hosted zone → 도메인 입력
3. `terraform apply` 후 `terraform output route53_nameservers` 에 표시되는 네임서버 4개를 외부 등록기관 콘솔의 네임서버 칸에 입력
4. DNS 전파 (수십 분 ~ 수 시간)

### 3) 변수 설정
```bash
cd infra/ec2
cp terraform.tfvars.example terraform.tfvars
# 도메인 샀으면 domain_name = "example.com" / tls_email = "you@example.com" 채움.
# 안 샀으면 그대로 두면 nip.io 자동 사용.
```

### 4) 첫 apply
```bash
terraform init
terraform plan -out tfplan
terraform apply tfplan
# 5분 안에 완료. 마지막에 host_url 출력.
```

### 5) 부팅 대기 (5–10분)
EC2 가 켜진 뒤 `user_data` 가 자동으로 진행:
- Docker / docker compose / git 설치
- 데이터 EBS 마운트
- `git clone` Kestrel
- `.env` 자동 생성 (JWT_SECRET / DB password 모두 random)
- Caddy 설정 + Let's Encrypt 인증서 자동 발급
- `docker compose up -d --build` (백엔드 + 프론트엔드 빌드 ~3분)

진행 상황은 SSM Session Manager 로 들어가 확인:
```bash
aws ssm start-session --target $(terraform output -raw instance_id)
sudo tail -f /var/log/kestrel-bootstrap.log
```

### 6) 접속
```bash
terraform output host_url
# https://1.2.3.4.nip.io  (도메인 미설정 시)
# 또는 https://kestrel.example.com
```
브라우저로 열어서 회원가입 → `initial_admin_emails` 이메일이면 자동 admin.

### 7) 일상 운영

| 작업 | 방법 |
|---|---|
| 코드 업데이트 | SSM 으로 접속 → `cd /opt/kestrel && git pull && docker compose up -d --build` |
| 로그 확인 | `docker compose logs -f backend` 등 |
| DB 백업 | AWS Backup 이 daily snapshot — 추가 작업 없음 |
| DB 복구 | AWS Console → Backup → snapshot 선택 → restore → 새 EBS 만들고 인스턴스에 attach |
| 인스턴스 교체 | `terraform taint aws_instance.host && terraform apply` (데이터 EBS 자동 detach → 새 인스턴스에 attach → user_data 가 기존 데이터 그대로 mount) |
| 비용 확인 | AWS Console → Billing → "이번 달 예상 비용" |

### 8) 정리

전부 지우고 싶으면:
```bash
terraform destroy
```
⚠️ 데이터 EBS 도 함께 삭제됩니다. 보존하고 싶다면 먼저 snapshot 을 만들거나
`main.tf` 의 `aws_ebs_volume.data` 에 `lifecycle { prevent_destroy = true }`
를 켜 두세요.

## 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| 첫 부팅 후 https 가 안 됨 (Connection refused) | user_data 가 아직 진행 중 — SSM 으로 들어가 `journalctl -u kestrel.service -f` |
| TLS 인증서 발급 실패 | DNS 가 EIP 를 가리키는지 확인. nip.io 사용 시는 자동. 본인 도메인이면 A 레코드 점검 |
| 컨테이너 OOMKilled | t4g.small (2 GB) 가 부족 — `instance_type = "t4g.medium"` (4 GB) 으로 올리고 `terraform apply` |
| 디스크 부족 | `data_volume_size_gb = 50` 으로 올리고 `terraform apply` → EBS 가 grow 됨. SSM 으로 들어가 `sudo resize2fs $(blkid -L kestrel-data)` 실행 |
