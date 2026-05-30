# Kestrel — Infrastructure (AWS)

전체 인프라를 Terraform 으로 정의합니다. **EC2 인스턴스를 직접 관리하는 컴포넌트는
하나도 없도록** 설계 — 전부 managed 서비스(RDS, Fargate, EFS, CloudFront, Secrets Manager).

## 단계별 가이드

따라하기 → [`GUIDE.md`](./GUIDE.md)

## 빠른 명령

```bash
# 1) state 백엔드 부트스트랩 (한 번만)
cd bootstrap && ./bootstrap.sh

# 2) backend 블록 활성화 (versions.tf 의 주석 풀기)

# 3) 변수
cd ..
cp terraform.tfvars.example terraform.tfvars   # 필요 시 값 수정

# 4) 인프라 생성
terraform init
terraform plan
terraform apply
```

## 아키텍처

```
              ┌────────────────────┐
              │ CloudFront (TLS)   │   ← 사용자 진입 (https://d123.cloudfront.net)
              └─────────┬──────────┘
                        │ HTTP (SG: CloudFront prefix list)
                ┌───────▼────────┐
                │  ALB (public)  │   /api/* → api-tg, default → frontend-tg
                └─┬────────────┬─┘
        ┌─────────┘            └────────┐
   ┌────▼─────┐               ┌─────────▼────────┐
   │ Frontend │               │ API (FastAPI)    │
   │ (Next.js)│               │ Fargate Spot     │
   │ Fargate  │               │ desired=1+spot   │
   └────┬─────┘               └─────┬────────────┘
        │ Service Connect (.internal)│
        ▼                            ▼
   ┌────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐
   │ Redis      │  │ Meilisearch  │  │ RDS          │  │ Scheduler   │
   │ on Fargate │  │ on Fargate   │  │ PostgreSQL   │  │ APScheduler │
   │ + EFS      │  │ + EFS        │  │ t4g.micro    │  │ Fargate ×1  │
   └────────────┘  └──────────────┘  └──────────────┘  └─────────────┘
```

## 비용 (KRW 기준 약 ₩130k/월, Free Tier 첫 해 약 ₩90k)

자세한 내역은 [`GUIDE.md`](./GUIDE.md#비용-예상) 참고.

## 모듈 인덱스

| 모듈 | 책임 |
|---|---|
| `network` | VPC, 2 AZ public/private 서브넷, NAT Gateway 1개, S3 endpoint |
| `security` | Security Group 6종 (ALB, ECS, DB, Redis, Meili, EFS) |
| `secrets` | Secrets Manager (DB 자격, 앱 시크릿, DATABASE_URL) |
| `db` | RDS PostgreSQL 16 (`db.t4g.micro`) |
| `cache` | Redis 7 on Fargate + EFS persistence |
| `search` | Meilisearch on Fargate + EFS |
| `ecr` | ECR 레포 (api, frontend) + lifecycle policy |
| `ecs_cluster` | ECS Cluster + Fargate Spot capacity + IAM roles |
| `alb` | ALB + path routing (`/api/*` vs default) |
| `ecs_service_api` | FastAPI service + autoscaling |
| `ecs_service_scheduler` | APScheduler single-instance service |
| `ecs_service_frontend` | Next.js standalone service |
| `cdn` | CloudFront + ACM (optional) + Route53 (optional) |
| `observability` | SNS 알림 토픽 + monthly budget alarm |

## CI/CD

GitHub Actions workflow → [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)

OIDC trust 셋업 → [`bootstrap/github-oidc.tf.example`](./bootstrap/github-oidc.tf.example)
