###############################################################################
# Kestrel — 단일 EC2 인스턴스 + Docker Compose 운영 스택 (PR 10-CU).
#
# 설계:
#   - public subnet 1개 + EC2 1대 + EIP + 데이터용 EBS 별도 + AWS Backup.
#   - VPC 안에 RDS/ALB/NAT 없음. 인스턴스에 직접 PostgreSQL/Redis/Meili 컨테이너.
#   - 사용자 데이터 = (1) PostgreSQL 볼륨, (2) Claude 자격증명, (3) MITRE/vulhub
#     repo — 모두 데이터 EBS 의 ``/data`` 에. AWS Backup 이 daily snapshot.
#   - 인스턴스가 죽거나 교체되면 EBS detach → 새 인스턴스에 attach 만 하면
#     데이터 그대로 복구. user_data 가 자동으로 mount + docker compose up.
###############################################################################

locals {
  name_prefix = "kestrel-${var.env}"
}

data "aws_availability_zones" "azs" {
  state = "available"
}

# ── 네트워크 ──────────────────────────────────────────────────
resource "aws_vpc" "this" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.30.1.0/24"
  availability_zone       = data.aws_availability_zones.azs.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name_prefix}-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ── 보안 그룹 ─────────────────────────────────────────────────
resource "aws_security_group" "host" {
  name        = "${local.name_prefix}-host-sg"
  description = "Kestrel single-host: HTTPS + optional SSH"
  vpc_id      = aws_vpc.this.id

  # 80 (Caddy HTTP redirect + Let's Encrypt HTTP-01 challenge)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for Caddy autoredirect and ACME challenge"
  }

  # 443 (Caddy TLS)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS via Caddy"
  }

  # SSH — only opened when ssh_allowed_cidr is set; otherwise use SSM.
  dynamic "ingress" {
    for_each = var.ssh_allowed_cidr == "" ? [] : [1]
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.ssh_allowed_cidr]
      description = "SSH for operator"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound for upstream APIs, Docker Hub, ACME"
  }

  tags = { Name = "${local.name_prefix}-host-sg" }
}

# ── IAM (SSM Session Manager + AWS Backup) ───────────────────
resource "aws_iam_role" "host" {
  name = "${local.name_prefix}-host-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# SSM agent 가 Session Manager 로 들어올 수 있게 — SSH 키 관리 불필요.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "host" {
  name = "${local.name_prefix}-host-profile"
  role = aws_iam_role.host.name
}

# ── AMI — Amazon Linux 2023 ARM (graviton, t4g 호환) ─────────
data "aws_ami" "al2023_arm" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# ── 데이터 EBS — 인스턴스와 분리해 영속화 ────────────────────
resource "aws_ebs_volume" "data" {
  availability_zone = data.aws_availability_zones.azs.names[0]
  size              = var.data_volume_size_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${local.name_prefix}-data" }

  # 데이터 보존이 최우선 — Terraform 이 destroy 해도 EBS 는 살리고 싶으면
  # 아래 lifecycle 을 켜라. 학습용으로는 destroy 가능하도록 두는 게 편하다.
  # lifecycle { prevent_destroy = true }
}

# ── EC2 인스턴스 ─────────────────────────────────────────────
resource "aws_instance" "host" {
  ami                         = data.aws_ami.al2023_arm.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.host.id]
  iam_instance_profile        = aws_iam_instance_profile.host.name
  associate_public_ip_address = true

  # 부트 디스크 — 작게. Docker root 는 데이터 EBS 의 /data/docker 로 이동.
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    DOMAIN               = var.domain_name
    TLS_EMAIL            = var.tls_email
    INITIAL_ADMIN_EMAILS = var.initial_admin_emails
    GIT_REPO_URL         = var.git_repo_url
    GIT_BRANCH           = var.git_branch
    DATA_VOLUME_DEVICE   = "/dev/sdb"
  })

  # user_data 가 EBS 마운트를 시도하므로 인스턴스 생성 직후에 attach 도 필요.
  depends_on = [aws_ebs_volume.data]

  tags = { Name = "${local.name_prefix}-host" }

  lifecycle {
    # user_data 변경만으로 인스턴스 강제 교체되는 사고 방지.
    ignore_changes = [user_data, ami]
  }
}

# EBS 를 인스턴스에 attach (sdb = nvme1n1 안에서 보임).
resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.host.id
  stop_instance_before_detaching = true
}

# ── Elastic IP — 인스턴스 재기동에도 같은 IP 유지 ────────────
resource "aws_eip" "host" {
  instance = aws_instance.host.id
  domain   = "vpc"
  tags     = { Name = "${local.name_prefix}-eip" }
}

# ── Route53 — 도메인이 설정된 경우만 A 레코드 자동 생성 ─────
# 도메인 자체는 Route53 콘솔에서 구매 (또는 외부 구매 후 네임서버 위임).
# Hosted zone 은 도메인 등록 시 Route53 이 자동 만들어 주므로 여기서는
# data source 로 lookup 만 한다.
data "aws_route53_zone" "this" {
  count        = var.domain_name == "" ? 0 : 1
  name         = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "apex" {
  count   = var.domain_name == "" ? 0 : 1
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 300
  records = [aws_eip.host.public_ip]
}

# www 도 같은 IP 로 (선택적 — 도메인 등록자가 www 도 원할 때).
resource "aws_route53_record" "www" {
  count   = var.domain_name == "" ? 0 : 1
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = "www.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.host.public_ip]
}

# ── AWS Backup — 데이터 EBS daily snapshot, 7일 보존 ─────────
resource "aws_iam_role" "backup" {
  name = "${local.name_prefix}-backup-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup_default" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_vault" "this" {
  name = "${local.name_prefix}-vault"
}

resource "aws_backup_plan" "daily" {
  name = "${local.name_prefix}-daily"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 18 * * ? *)" # 매일 18:00 UTC (KST 03:00)
    lifecycle {
      delete_after = 7 # 7일 보존
    }
  }
}

resource "aws_backup_selection" "data" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "${local.name_prefix}-data-selection"
  plan_id      = aws_backup_plan.daily.id
  resources    = [aws_ebs_volume.data.arn]
}
