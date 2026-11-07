# The first "bait" bucket, kept around as a placeholder for when data-event
# detection becomes possible again - cloudtrail:CreateTrail is currently
# denied account-wide by an org SCP, so there's no trail to wire this into
# yet. See eventbridge.tf for the current state of the detection pipeline.
resource "aws_s3_bucket" "demo" {
  bucket = "trippycreds-demo-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
