# Kestrel — AWS 마이그레이션 가이드

이 문서는 처음 AWS를 다루는 분도 따라할 수 있도록 단계별로 정리한 지침서입니다.
중간에 막히면 GUIDE.md의 [트러블슈팅](#트러블슈팅) 섹션을 먼저 보세요.

---

## 비용 예상

| 항목 | 월 비용 (대략, ap-northeast-2) |
|---|---|
| ALB | $20 |
| NAT Gateway × 1 | $32 |
| Fargate Spot (api 1 + scheduler 1 + frontend 1 + redis 1 + meili 1, total ~1.8 vCPU/3.5 GB) | $25 |
| RDS PostgreSQL `db.t4g.micro` | $13 (**Free Tier 첫 12개월 무료**) |
| EFS 1 GB | $0.30 |
| Secrets Manager × 3 | $1.20 |
| CloudFront | 변동 (~월 1 TB까지 거의 무료) |
| CloudWatch Logs (30일 보존) | $5 |
| **합계** | **약 $96/월** (Free Tier 적용 시 ~$70) |

> 트래픽 증가 / Aurora 전환 / Multi-AZ 활성화 시 비용 증가. `infra/variables.tf`에서
> 사이즈 조절 가능.

---

## 0. 준비물 체크리스트

- [ ] **AWS 계정** (root 또는 Admin 권한 IAM 사용자)
- [ ] **AWS CLI v2** 설치 — <https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html>
- [ ] **Terraform ≥ 1.7** — <https://developer.hashicorp.com/terraform/install>
- [ ] **Docker** (로컬에서 이미지 빌드 시) — 이미 설치돼 있으면 OK
- [ ] **GitHub CLI** (선택, CI 설정 시)

설치 확인:
```bash
aws --version            # aws-cli/2.x
terraform version        # Terraform v1.7+
docker version
```

---

## 1. AWS 자격증명 설정

콘솔에서 **IAM → Users → Create user**로 사용자 만들고 `AdministratorAccess` 정책을 일시 부여.
액세스 키 발급 후:

```bash
aws configure
# AWS Access Key ID:     [발급받은 키]
# AWS Secret Access Key: [발급받은 시크릿]
# Default region:        ap-northeast-2
# Default output format: json
```

확인:
```bash
aws sts get-caller-identity
# {
#   "Account": "123456789012",
#   "Arn":     "arn:aws:iam::123456789012:user/your-name"
# }
```

> **운영 단계에서는** 별도 `kestrel-deployer` IAM 사용자/Role을 만들고 최소 권한만 부여하세요.
> 초기엔 Admin으로 빠르게 진행하는 게 단순합니다.

---

## 2. Terraform state 백엔드 부트스트랩

state 파일은 S3에 저장하고 동시 실행 방지용 lock은 DynamoDB에 둡니다.
부트스트랩 스크립트가 한 번에 만들어 줍니다.

```bash
cd infra/bootstrap
./bootstrap.sh
```

스크립트가 끝나면 출력된 `backend "s3" { ... }` 블록을 복사해
`infra/versions.tf`의 주석 처리된 블록과 교체하고 주석을 푸세요.

---

## 3. 변수 채우기

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars` 열고 필요한 값 채움. 도메인이 없으면 그대로 두면 됩니다 — CloudFront 기본 도메인이 사용됩니다.

---

## 4. 인프라 생성

```bash
terraform init        # provider 다운로드 + backend 초기화
terraform plan        # 만들어질 리소스 미리보기
terraform apply       # 실제 생성 (15-20분 소요)
```

생성 완료되면 다음 값들이 출력됩니다:

```
Outputs:

  frontend_url             = "https://d3xyz123abc.cloudfront.net"
  api_url                  = "https://d3xyz123abc.cloudfront.net/api/v1"
  ecr_api_repo             = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/kestrel-prod-api"
  ecr_frontend_repo        = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/kestrel-prod-frontend"
  secret_app_arn           = "arn:aws:secretsmanager:..."
  ...
```

이때 ECS 서비스들은 "이미지 없음" 상태로 대기 중입니다. 다음 단계에서 이미지 푸시.

---

## 5. 이미지 빌드 & ECR 푸시

ECR에 로그인:
```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=ap-northeast-2
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
```

백엔드 이미지:
```bash
cd backend
docker build -t kestrel-api .
docker tag kestrel-api:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/kestrel-prod-api:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/kestrel-prod-api:latest
```

프론트엔드 이미지:
```bash
cd ../frontend
docker build -t kestrel-frontend .
docker tag kestrel-frontend:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/kestrel-prod-frontend:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/kestrel-prod-frontend:latest
```

ECS 서비스 강제 재배포:
```bash
aws ecs update-service --cluster kestrel-prod --service kestrel-prod-api       --force-new-deployment --region $REGION
aws ecs update-service --cluster kestrel-prod --service kestrel-prod-scheduler --force-new-deployment --region $REGION
aws ecs update-service --cluster kestrel-prod --service kestrel-prod-frontend  --force-new-deployment --region $REGION
```

5-10분 후 ECS 콘솔에서 task가 RUNNING으로 바뀌면 완료.

---

## 6. 외부 API 키 채우기

`Secrets Manager` 콘솔에서 `kestrel-prod/app/runtime` 시크릿을 열어
다음 키들의 값을 채웁니다:

| 키 | 어디서 |
|---|---|
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key |
| `GITHUB_TOKEN` | https://github.com/settings/tokens (read:org 권한) |
| `ANTHROPIC_API_KEY` | https://console.anthropic.com/ |
| `SENTRY_DSN` | https://sentry.io (선택) |

변경 후 ECS API 서비스 재배포:
```bash
aws ecs update-service --cluster kestrel-prod --service kestrel-prod-api --force-new-deployment
```

---

## 7. 접속 확인

```bash
terraform output frontend_url
# https://d3xyz123abc.cloudfront.net
```

브라우저로 접속해서 Kestrel 대시보드가 뜨면 성공.

---

## 8. (선택) 자체 도메인 연결

도메인이 생기면:

1. Route 53에서 hosted zone 만들기 (예: `kestrel.com`)
2. 도메인 등록업체에 NS 레코드 등록
3. `infra/terraform.tfvars`에 추가:
   ```hcl
   domain_name     = "app.kestrel.com"
   route53_zone_id = "Z0123456789ABCDEFGHIJ"
   ```
4. `terraform apply` — ACM 인증서가 자동 발급되고 CloudFront에 연결됩니다.

---

## 9. CI/CD (선택)

`.github/workflows/deploy.yml`이 만들어져 있습니다.
GitHub repo의 Settings → Secrets에 다음 추가:

| Secret | 값 |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | OIDC role ARN (별도 생성 필요) |
| `AWS_REGION` | `ap-northeast-2` |

main에 push되면 자동으로 이미지 빌드 → ECR push → ECS 재배포.

---

## 트러블슈팅

### `terraform apply`가 RDS 생성에서 멈춰요
RDS는 첫 생성에 10-15분 걸립니다. `aws rds describe-db-instances` 로 진행 상황 확인.

### ECS task가 PENDING에서 진행 안 됨
- ECR에 이미지가 푸시됐는지 확인
- CloudWatch Logs `/ecs/kestrel-prod-*` 확인
- task가 NAT Gateway 통해 ECR pull 하려면 NAT 정상 동작 필요 (`aws ec2 describe-nat-gateways`)

### CloudFront URL 접속 시 502/504
- ALB 헬스체크가 통과하는지 확인 (ALB → Target groups)
- ECS task가 RUNNING + HEALTHY 인지 확인
- 백엔드: `/api/v1/health` 가 200 반환해야 함

### 모든 걸 삭제하고 다시 시작
```bash
terraform destroy           # 인프라 삭제
# state 백엔드(S3 버킷, DynamoDB)는 콘솔에서 수동 삭제
```

---

## 다음 단계

- [ ] CloudWatch 알람 설정 (CPU/메모리/5xx)
- [ ] WAF 추가 (`aws_wafv2_web_acl` → CloudFront 연결)
- [ ] Aurora Serverless v2로 DB 마이그레이션 (부하 증가 시)
- [ ] 멀티 환경(`dev` + `prod`) 분리
- [ ] OIDC 기반 CI/CD 자격증명
