package ecs

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AlicloudECSInstanceSensitiveUserdata(t *testing.T) {
	expectedCode := "alicloud-ecs-no-secrets-in-user-data"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "test block containing access keys",
			source: `
resource "alicloud_instance" "bad_example" {

	image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
	instance_type = "ecs.n4.large"
	
	user_data = <<EOF
	export ALICLOUD_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
	export ALICLOUD_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	export ALICLOUD_REGION=us-west-2 
	EOF
}			  
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "test block with no user data",
			source: `
resource "alicloud_ram_role" "good_profile" {
    // ...
}

resource "alicloud_instance" "good_example" {
	image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
	instance_type = "ecs.n4.large"

	ram_name = alicloud_ram_role.good_profile.arn
}
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "test block with no user data",
			source: `
resource "alicloud_ram_role" "good_profile" {
    // ...
}

resource "alicloud_instance" "good_example" {
  image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
  instance_type = "ecs.n4.large"
  
  ram_name = alicloud_ram_role.good_profile.arn

  user_data = "echo Hello, World! > /var/tmp/hello"
}
`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
