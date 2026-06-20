# Kestrel 인프라

이 디렉터리는 두 개의 스택으로 나뉜다. **운영(확정 아키텍처)은 `ec2/` 단 하나다.**

## `ec2/` — ✅ 확정 / 현재 운영 중

`www.kestrel.forum` 을 실제로 서비스하는 스택. 단일 EC2 호스트(`t4g.small`, arm64)
위에서 `docker compose` 로 전체 스택(Caddy · 프론트 · API · Postgres · Redis ·
Meilisearch)을 구동한다. 이미지는 GitHub Actions 가 GHCR 에 빌드해 올리고
(`/.github/workflows/build-images.yml`), 호스트는 그것을 pull 한다.

- 배포: 푸시 → CI 빌드 → 호스트에서 `scripts/deploy.sh` (`git pull && docker compose pull && up -d`)
- Terraform state 는 `ec2/` 안의 로컬 state (gitignore)

운영/배포 관련 변경은 **이 스택만** 기준으로 한다.

## `legacy-ecs/` — 🗄️ 레거시 / 미사용 (미배포)

초기에 검토했던 ECS Fargate(ALB · ECR · RDS · ElastiCache · CloudFront ·
Meilisearch) 모듈 모음. **현재 AWS 에 배포돼 있지 않으며 확정 아키텍처가 아니다.**
참고/히스토리 목적으로만 보존한다. 운영 판단에 사용하지 말 것.
