provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

# CloudFront ACM 인증서는 us-east-1 만 지원하므로 별도 alias.
# 자체 도메인을 붙일 때만 쓰입니다. 도메인 없으면 cdn 모듈이 ACM 생략.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.common_tags
  }
}
