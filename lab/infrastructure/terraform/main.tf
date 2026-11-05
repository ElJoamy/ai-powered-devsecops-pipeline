# STATIC ANALYSIS ONLY — intentionally insecure fixtures; never apply.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "lab" {
  cidr_block = "10.99.0.0/16"

  tags = {
    Name = "static-analysis-only-lab-vpc"
  }
}
