terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # aws_bedrockagentcore_agent_runtime を使うため v6 系が必要
      version = "~> 6.0"
    }
  }

  # 複数人での運用やCI/CDから実行する場合はリモートバックエンドを推奨。
  # 詳細は docs/deployment.md の「State管理」を参照。
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "security-hub-agent/terraform.tfstate"
  #   region = "ap-northeast-1"
  # }
}

provider "aws" {
  region = var.aws_region
}
