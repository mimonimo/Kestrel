#!/usr/bin/env bash
# Terraform state 백엔드 (S3 + DynamoDB) 를 한 번 만들고 끝나는 부트스트랩.
# infra/versions.tf 의 backend "s3" 블록 주석을 풀고 값 채우기 전에 한 번만 실행하세요.

set -euo pipefail

REGION="${AWS_REGION:-ap-northeast-2}"
PROJECT="${PROJECT:-kestrel}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${PROJECT}-tfstate-${ACCOUNT_ID}"
TABLE="${PROJECT}-tfstate-lock"

echo "▸ AWS Account : ${ACCOUNT_ID}"
echo "▸ Region      : ${REGION}"
echo "▸ Bucket      : ${BUCKET}"
echo "▸ Lock table  : ${TABLE}"
echo

# 1. State 버킷 (없으면 생성)
if ! aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  echo "▸ 버킷 생성 중…"
  if [ "${REGION}" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}"
  else
    aws s3api create-bucket --bucket "${BUCKET}" --region "${REGION}" \
      --create-bucket-configuration LocationConstraint="${REGION}"
  fi
fi

# 버킷 보호 — 버전 관리, 암호화, public 차단
aws s3api put-bucket-versioning --bucket "${BUCKET}" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "${BUCKET}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-public-access-block --bucket "${BUCKET}" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 2. 락 테이블
if ! aws dynamodb describe-table --table-name "${TABLE}" --region "${REGION}" >/dev/null 2>&1; then
  echo "▸ DynamoDB 락 테이블 생성 중…"
  aws dynamodb create-table \
    --table-name "${TABLE}" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "${REGION}"
  aws dynamodb wait table-exists --table-name "${TABLE}" --region "${REGION}"
fi

echo
echo "✅ 완료. infra/versions.tf 의 backend 's3' 블록 주석을 풀고 아래 값으로 채우세요:"
cat <<EOF

  backend "s3" {
    bucket         = "${BUCKET}"
    key            = "${PROJECT}/prod/terraform.tfstate"
    region         = "${REGION}"
    dynamodb_table = "${TABLE}"
    encrypt        = true
  }

그 다음:
  cd infra
  terraform init
  cp terraform.tfvars.example terraform.tfvars   # 값 채우기
  terraform plan
  terraform apply
EOF
