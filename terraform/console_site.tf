resource "aws_s3_bucket" "console" {
  bucket = "trippycreds-console-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "console" {
  bucket = aws_s3_bucket.console.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "console" {
  name                              = "trippycreds-console"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "console" {
  enabled             = true
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.console.bucket_regional_domain_name
    origin_id                = "console-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.console.id
  }

  default_cache_behavior {
    target_origin_id       = "console-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

data "aws_iam_policy_document" "console_bucket_policy" {
  statement {
    sid    = "AllowCloudFrontRead"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.console.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.console.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "console" {
  bucket = aws_s3_bucket.console.id
  policy = data.aws_iam_policy_document.console_bucket_policy.json
}

locals {
  console_static_files = {
    "index.html" = "text/html"
    "app.js"     = "application/javascript"
    "style.css"  = "text/css"
  }
}

resource "aws_s3_object" "console_static" {
  for_each     = local.console_static_files
  bucket       = aws_s3_bucket.console.id
  key          = each.key
  source       = "${path.module}/../console/${each.key}"
  content_type = each.value
  etag         = filemd5("${path.module}/../console/${each.key}")
}

# No build-time config baked into the SPA - it fetches this at runtime.
resource "aws_s3_object" "console_config" {
  bucket       = aws_s3_bucket.console.id
  key          = "config.json"
  content_type = "application/json"
  content = jsonencode({
    apiBaseUrl      = aws_apigatewayv2_stage.api.invoke_url
    cognitoDomain   = "https://${aws_cognito_user_pool_domain.console.domain}.auth.${var.aws_region}.amazoncognito.com"
    cognitoClientId = aws_cognito_user_pool_client.console.id
    region          = var.aws_region
  })
}

# Static assets alone don't force CloudFront to re-fetch from the origin
# within its cache TTL - invalidate on every content change so edits show up
# immediately instead of waiting it out.
resource "null_resource" "console_invalidation" {
  triggers = {
    content_hash = sha1(join("", concat(
      [for f in keys(local.console_static_files) : filemd5("${path.module}/../console/${f}")],
      [aws_s3_object.console_config.content],
    )))
  }

  provisioner "local-exec" {
    command = "aws cloudfront create-invalidation --distribution-id ${aws_cloudfront_distribution.console.id} --paths '/*' --profile ${var.aws_profile} --region us-east-1"
  }

  depends_on = [aws_s3_object.console_static, aws_s3_object.console_config]
}
