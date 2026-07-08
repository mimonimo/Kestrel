provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "kestrel"
      Environment = var.env
      ManagedBy   = "terraform"
      Stack       = "ec2-single"
    }
  }
}

# Route53 헬스체크의 CloudWatch 지표(AWS/Route53 HealthCheckStatus)는
# us-east-1 에만 발행된다 — 감시 알람과 알람이 쏠 SNS 토픽도 같은 리전에
# 있어야 해서 별도 alias 를 둔다 (availability.tf 에서 사용).
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
  default_tags {
    tags = {
      Project     = "kestrel"
      Environment = var.env
      ManagedBy   = "terraform"
      Stack       = "ec2-single"
    }
  }
}
