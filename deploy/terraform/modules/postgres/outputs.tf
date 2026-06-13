output "endpoint" {
  description = "Postgres host:port."
  value       = aws_db_instance.this.endpoint
}

output "address" {
  description = "Postgres hostname."
  value       = aws_db_instance.this.address
}

output "port" {
  description = "Postgres port."
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Initial database name."
  value       = aws_db_instance.this.db_name
}

output "username" {
  description = "Master username."
  value       = aws_db_instance.this.username
}

output "security_group_id" {
  description = "Security group protecting the instance."
  value       = aws_security_group.this.id
}

output "dsn" {
  description = "KSEAL_POSTGRES_DSN connection string (sslmode=require)."
  sensitive   = true
  value = format(
    "postgres://%s:%s@%s:%d/%s?sslmode=require",
    aws_db_instance.this.username,
    random_password.master.result,
    aws_db_instance.this.address,
    aws_db_instance.this.port,
    aws_db_instance.this.db_name,
  )
}

output "master_password" {
  description = "Generated master password."
  sensitive   = true
  value       = random_password.master.result
}
