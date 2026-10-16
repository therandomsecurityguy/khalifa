resource "aws_ecr_repository" "images" {
  for_each = local.repository_names

  name                 = each.value
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Name      = each.value
    Component = each.key
  })
}
