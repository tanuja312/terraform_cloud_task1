provider "aws" {

region = "ap-south-1"
profile = "tanuja"
}
resource "tls_private_key" "example122" {
  algorithm   = "RSA"
 
}


resource "aws_key_pair" "instkey" {
  key_name   = "keyos"
  public_key =  tls_private_key.example122.public_key_openssh 

}

resource "local_file" "mykeyfile" {
    content     = tls_private_key.example122.private_key_pem 
    filename =  "keyos.pem"
}


resource "aws_security_group" "myfirewall" {
  name        = "firewall_os"
  description = "create firewall for my os"
  vpc_id      = "vpc-28cffc40"

  ingress {
    description = "allow ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

    ingress {
    description = "allow web service"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "firewall_os"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name =  "keyos"
  security_groups= [ "firewall_os" ]

  tags = {
    Name = "myos"
  }
}

resource "aws_ebs_volume" "ebs" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1

  tags = {
    Name = "myebs"
  }
}


resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.ebs.id
  instance_id = aws_instance.web.id
  force_detach = true
}

resource "null_resource" "nullremote11"  {

depends_on = [
    aws_volume_attachment.ebs_att
  ]
 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key  = tls_private_key.example122.private_key_pem 
    host     = aws_instance.web.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd git -y",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo mkfs.ext4  /dev/xvdf",
      "sudo mount  /dev/xvdf  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/tanuja312/cloudtask1.git /var/www/html/"
    ]
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "my-bucket112222"
  acl    = "private"
  versioning {
    enabled = true
  }

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id

  policy = <<POLICY
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "AllowPublicRead",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket112222/*"
        }
    ]
}
POLICY
}
resource "null_resource" "nulllocal2"  {
       
	provisioner "local-exec" {
            command = "rmdir /S /Q img"
  	}
        
	provisioner "local-exec" {
            command = "git clone https://github.com/tanuja312/cloudtask11.git img"
  	}
}

resource "aws_s3_bucket_public_access_block" "b111" {
  bucket = aws_s3_bucket.b.id

  block_public_acls   = false
  block_public_policy = false
}


resource "aws_s3_bucket_object" "object" {
  depends_on =[ null_resource.nulllocal2 ,aws_s3_bucket.b ]
  bucket = "my-bucket112222"
  key    = "pikachu.jpg"
  source = "img/pikachu.jpg"
  content_type = "image/jpeg"
  acl = "public-read"
  content_disposition = "inline"
  content_encoding = "base64"
  
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Some comment"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = "S3-my-bucket112222"

  /*  s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
   */
      custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        } 
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
   default_root_object = "pikachu.jpg"


  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-my-bucket112222"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "null_resource" "nullremote12"  {

depends_on = [
    aws_cloudfront_distribution.s3_distribution
  ]
 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key  = tls_private_key.example122.private_key_pem 
    host     = aws_instance.web.public_ip
  }

  provisioner "remote-exec" {
    inline = [
    
      "sudo sed ' /img/ c \"<img src= \"http://${aws_cloudfront_distribution.s3_distribution.domain_name}\" >\" ' /var/www/html/index.html"
    ]
  }
}



resource "null_resource" "nulllocal1"  {


depends_on = [
    null_resource.nullremote11,
    aws_cloudfront_distribution.s3_distribution,
    null_resource.nullremote12
  ]

	provisioner "local-exec" {
	    command = " start chrome  ${aws_instance.web.public_ip}"
  	}
}
