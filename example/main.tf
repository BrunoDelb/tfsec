resource "alicloud_instance" "my_infra" {

  image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
  instance_type = "ecs.n4.large"

  user_data = <<EOF
export ALICLOUD_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
export ALICLOUD_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export ALICLOUD_REGION=us-west-2 
EOF
}

resource "alicloud_oss_bucket" "bad_example" {

}

resource "alicloud_oss_bucket" "my-bucket" {
	
}
