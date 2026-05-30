# 루트 — 각 모듈을 호출.
# 적용 순서가 의미 있는 것은 depends_on / output 참조로 자동 처리됩니다.

module "network" {
  source      = "./modules/network"
  name_prefix = local.name_prefix
  vpc_cidr    = var.vpc_cidr
  az_count    = var.az_count
}

module "security" {
  source      = "./modules/security"
  name_prefix = local.name_prefix
  vpc_id      = module.network.vpc_id
}

module "secrets" {
  source             = "./modules/secrets"
  name_prefix        = local.name_prefix
  db_master_username = var.db_master_username
}

module "db" {
  source               = "./modules/db"
  name_prefix          = local.name_prefix
  env                  = var.env
  private_subnet_ids   = module.network.private_subnet_ids
  db_sg_id             = module.security.db_sg_id
  db_name              = var.db_name
  db_master_username   = var.db_master_username
  db_master_password   = module.secrets.db_master_password
  db_instance_class    = var.db_instance_class
  db_allocated_storage = var.db_allocated_storage
}

module "ecr" {
  source      = "./modules/ecr"
  name_prefix = local.name_prefix
}

module "ecs_cluster" {
  source           = "./modules/ecs_cluster"
  name_prefix      = local.name_prefix
  app_secret_arn   = module.secrets.app_secret_arn
  db_secret_arn    = module.secrets.db_master_secret_arn
}

module "cache" {
  source             = "./modules/cache"
  name_prefix        = local.name_prefix
  cluster_arn        = module.ecs_cluster.cluster_arn
  private_subnet_ids = module.network.private_subnet_ids
  redis_sg_id        = module.security.redis_sg_id
  efs_sg_id          = module.security.efs_sg_id
  task_exec_role_arn = module.ecs_cluster.task_exec_role_arn
  task_role_arn      = module.ecs_cluster.task_role_arn
  cpu                = var.redis_cpu
  memory             = var.redis_memory
}

module "search" {
  source             = "./modules/search"
  name_prefix        = local.name_prefix
  cluster_arn        = module.ecs_cluster.cluster_arn
  private_subnet_ids = module.network.private_subnet_ids
  meili_sg_id        = module.security.meili_sg_id
  efs_sg_id          = module.security.efs_sg_id
  task_exec_role_arn = module.ecs_cluster.task_exec_role_arn
  task_role_arn      = module.ecs_cluster.task_role_arn
  app_secret_arn     = module.secrets.app_secret_arn
  cpu                = var.meili_cpu
  memory             = var.meili_memory
}

module "alb" {
  source             = "./modules/alb"
  name_prefix        = local.name_prefix
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  alb_sg_id          = module.security.alb_sg_id
}

module "ecs_service_api" {
  source                = "./modules/ecs_service_api"
  name_prefix           = local.name_prefix
  cluster_arn           = module.ecs_cluster.cluster_arn
  private_subnet_ids    = module.network.private_subnet_ids
  ecs_tasks_sg_id       = module.security.ecs_tasks_sg_id
  task_exec_role_arn    = module.ecs_cluster.task_exec_role_arn
  task_role_arn         = module.ecs_cluster.task_role_arn
  image                 = "${module.ecr.api_repo_url}:${var.image_tag_api}"
  cpu                   = var.api_cpu
  memory                = var.api_memory
  desired_count         = var.api_desired_count
  alb_target_group_arn  = module.alb.api_target_group_arn
  alb_listener_arn      = module.alb.https_listener_arn
  database_url_secret_arn = module.secrets.database_url_secret_arn
  app_secret_arn        = module.secrets.app_secret_arn
  redis_url             = module.cache.redis_url
  meili_host            = module.search.meili_host
  cors_origins_json     = "[\"https://${module.cdn.frontend_url}\"]"
}

module "ecs_service_scheduler" {
  source                = "./modules/ecs_service_scheduler"
  name_prefix           = local.name_prefix
  cluster_arn           = module.ecs_cluster.cluster_arn
  private_subnet_ids    = module.network.private_subnet_ids
  ecs_tasks_sg_id       = module.security.ecs_tasks_sg_id
  task_exec_role_arn    = module.ecs_cluster.task_exec_role_arn
  task_role_arn         = module.ecs_cluster.task_role_arn
  image                 = "${module.ecr.api_repo_url}:${var.image_tag_scheduler}"
  cpu                   = var.scheduler_cpu
  memory                = var.scheduler_memory
  database_url_secret_arn = module.secrets.database_url_secret_arn
  app_secret_arn        = module.secrets.app_secret_arn
  redis_url             = module.cache.redis_url
  meili_host            = module.search.meili_host
}

module "ecs_service_frontend" {
  source               = "./modules/ecs_service_frontend"
  name_prefix          = local.name_prefix
  cluster_arn          = module.ecs_cluster.cluster_arn
  private_subnet_ids   = module.network.private_subnet_ids
  ecs_tasks_sg_id      = module.security.ecs_tasks_sg_id
  task_exec_role_arn   = module.ecs_cluster.task_exec_role_arn
  task_role_arn        = module.ecs_cluster.task_role_arn
  image                = "${module.ecr.frontend_repo_url}:${var.image_tag_frontend}"
  cpu                  = var.frontend_cpu
  memory               = var.frontend_memory
  desired_count        = var.frontend_desired_count
  alb_target_group_arn = module.alb.frontend_target_group_arn
  alb_listener_arn     = module.alb.https_listener_arn
  api_base_url         = "https://${module.cdn.frontend_url}/api/v1"
}

module "cdn" {
  source           = "./modules/cdn"
  providers = {
    aws.us_east_1 = aws.us_east_1
  }
  name_prefix      = local.name_prefix
  alb_dns_name     = module.alb.alb_dns_name
  domain_name      = var.domain_name
  route53_zone_id  = var.route53_zone_id
}

module "observability" {
  source      = "./modules/observability"
  name_prefix = local.name_prefix
}
