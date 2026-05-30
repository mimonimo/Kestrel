terraform {
  required_version = ">= 1.7"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.60" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }

  # 첫 apply 는 local state — 작성 즉시 학습용 / 단일 사용자 운영 시에는
  # 굳이 S3 backend 가 필요 없음. 다중 협업이 생기면 그때 옮기면 됨.
  # backend "s3" {
  #   bucket         = "kestrel-tfstate-<acct>"
  #   key            = "ec2/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "kestrel-tfstate-lock"
  #   encrypt        = true
  # }
}
