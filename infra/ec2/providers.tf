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
