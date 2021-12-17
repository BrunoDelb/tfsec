package oss

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AlicloudUnencryptedOSSBucket(t *testing.T) {
	expectedCode := "alicloud-oss-enable-bucket-encryption"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no server_side_encryption_rule alicloud_oss_bucket",
			source: `
resource "alicloud_oss_bucket" "my-bucket" {
	
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check no server_side_encryption_rule alicloud_oss_bucket",
			source: `
resource "alicloud_oss_bucket" "my-bucket" {
  bucket = "mybucket"

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "your-kms-key-id"
  }
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "no error when server_side_encryption_rule provided",
			source: `
resource "alicloud_oss_bucket" "this" {
   bucket = "accesslog"
   acl    = "private"
 
  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "your-kms-key-id"
  }
 
     versioning {
     }
 
     #checkov:skip=CKV_ALI_18:This OSS does not need logging to be enabled
     #tfsec:ignore:ALI002 This OSS does not need logging to be enabled
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
