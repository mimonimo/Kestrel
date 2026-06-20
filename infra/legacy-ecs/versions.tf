terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # 부트스트랩 완료 후 backend 활성화 — bootstrap/README 참고.
  # backend "s3" {
  #   bucket         = "kestrel-tfstate-XXXXXXXXXXXX"
  #   key            = "prod/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "kestrel-tfstate-lock"
  #   encrypt        = true
  # }
}
