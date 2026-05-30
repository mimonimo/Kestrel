variable "name_prefix"          { type = string }
variable "env"                  { type = string }
variable "private_subnet_ids"   { type = list(string) }
variable "db_sg_id"             { type = string }
variable "db_name"              { type = string }
variable "db_master_username"   { type = string }
variable "db_master_password"   { type = string, sensitive = true }
variable "db_instance_class"    { type = string }
variable "db_allocated_storage" { type = number }
