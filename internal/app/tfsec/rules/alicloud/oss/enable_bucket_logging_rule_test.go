package oss

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AlicloudBucketLogging(t *testing.T) {
	expectedCode := "alicloud-oss-enable-bucket-logging"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check bucket with logging disabled",
			source: `
resource "alicloud_oss_bucket" "my-bucket" {
	
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check bucket with logging enabled",
			source: `
resource "alicloud_oss_bucket" "my-bucket" {
	logging {
		target_bucket = "target-bucket"
	}
}`,
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
