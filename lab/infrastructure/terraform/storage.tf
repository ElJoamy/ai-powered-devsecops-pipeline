# STATIC ANALYSIS ONLY — intentionally insecure fixtures; never apply.
resource "aws_s3_bucket" "lab_public" {
  # Dummy example name, not an existing bucket identifier.
  bucket = "devsecops-vulnerable-lab-static-example-not-for-use"
}

resource "aws_s3_bucket_public_access_block" "lab_public" {
  bucket = aws_s3_bucket.lab_public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "lab_public" {
  bucket = aws_s3_bucket.lab_public.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "lab_public" {
  bucket = aws_s3_bucket.lab_public.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_public_access_block.lab_public,
    aws_s3_bucket_ownership_controls.lab_public,
  ]
}

resource "aws_s3_bucket_policy" "lab_public_read" {
  bucket = aws_s3_bucket.lab_public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadExample"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.lab_public.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.lab_public]
}

# Deliberately omit any S3 server-side encryption configuration resource.
resource "aws_ebs_volume" "lab_unencrypted" {
  availability_zone = "us-east-1-example" # Dummy zone; not deployable.
  size              = 1
  type              = "gp3"
  encrypted         = false

  tags = {
    Name = "static-analysis-only-unencrypted-volume"
  }
}
