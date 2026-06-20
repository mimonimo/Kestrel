output "alb_sg_id"       { value = aws_security_group.alb.id }
output "ecs_tasks_sg_id" { value = aws_security_group.ecs_tasks.id }
output "meili_sg_id"     { value = aws_security_group.meili.id }
output "db_sg_id"        { value = aws_security_group.db.id }
output "redis_sg_id"     { value = aws_security_group.redis.id }
output "efs_sg_id"       { value = aws_security_group.efs.id }
