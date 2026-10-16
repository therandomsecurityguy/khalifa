resource "aws_security_group" "neptune" {
  name        = "${local.name}-neptune"
  description = "Neptune access for Khalifa EKS workloads"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${local.name}-neptune" })
}

resource "aws_vpc_security_group_ingress_rule" "neptune_nodes" {
  security_group_id            = aws_security_group.neptune.id
  referenced_security_group_id = var.node_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8182
  to_port                      = 8182
  description                  = "EKS nodes"
}

resource "aws_vpc_security_group_ingress_rule" "neptune_vpc" {
  security_group_id = aws_security_group.neptune.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 8182
  to_port           = 8182
  description       = "VPC pods"
}

resource "aws_vpc_security_group_egress_rule" "neptune" {
  security_group_id = aws_security_group.neptune.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_neptune_subnet_group" "this" {
  name       = local.name
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_neptune_cluster" "this" {
  cluster_identifier                  = local.name
  engine                              = "neptune"
  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  kms_key_arn                         = aws_kms_key.this.arn
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.name}-final"
  backup_retention_period             = 7
  preferred_backup_window             = "07:00-09:00"
  vpc_security_group_ids              = [aws_security_group.neptune.id]
  neptune_subnet_group_name           = aws_neptune_subnet_group.this.name
  copy_tags_to_snapshot               = true
  enable_cloudwatch_logs_exports      = ["audit"]

  serverless_v2_scaling_configuration {
    min_capacity = var.neptune_min_capacity
    max_capacity = var.neptune_max_capacity
  }

  tags = merge(var.tags, { Name = local.name })
}

data "aws_subnet" "private" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

locals {
  # Multi-AZ places the reader in a different AZ from the writer; the AZs come
  # from the private subnets, which the variable already requires to be two or
  # more. `element(..., 1)` wraps if only one distinct AZ is present.
  private_subnet_azs = distinct(sort([for subnet in data.aws_subnet.private : subnet.availability_zone]))
  neptune_reader_az  = element(local.private_subnet_azs, 1)
}

resource "aws_neptune_cluster_instance" "this" {
  identifier         = "${local.name}-1"
  cluster_identifier = aws_neptune_cluster.this.id
  instance_class     = "db.serverless"
  engine             = "neptune"

  tags = merge(var.tags, { Name = "${local.name}-1" })
}

# A second instance in another AZ makes the cluster Multi-AZ. Promotion tier 1
# scales with the writer, so it is at the right capacity to take over on
# failover (storage is already replicated across three AZs either way).
resource "aws_neptune_cluster_instance" "reader" {
  identifier         = "${local.name}-2"
  cluster_identifier = aws_neptune_cluster.this.id
  instance_class     = "db.serverless"
  engine             = "neptune"
  promotion_tier     = 1
  availability_zone  = local.neptune_reader_az

  tags = merge(var.tags, { Name = "${local.name}-2" })
}

resource "aws_cloudwatch_log_group" "neptune_audit" {
  name              = "/aws/neptune/${local.name}/audit"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.this.arn

  tags = merge(var.tags, { Name = "${local.name}-neptune-audit" })
}
