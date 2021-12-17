package oss

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "ALI017",
		Service:   "oss",
		ShortCode: "enable-bucket-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted OSS bucket.",
			Impact:     "The bucket objects could be read if compromised",
			Resolution: "Configure bucket encryption",
			Explanation: `
OSS Buckets should be encrypted with customer managed KMS keys and not default Alibaba Cloud managed keys, in order to allow granular control over access to specific buckets.
`,
			BadExample: []string{`
resource "alicloud_oss_bucket" "bad_example" {
  bucket = "mybucket"
}
`},
			GoodExample: []string{`
resource "alicloud_oss_bucket" "good_example" {
  bucket = "mybucket"

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "your-kms-key-id"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#server_side_encryption_rule",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_oss_bucket"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			if resourceBlock.MissingChild("server_side_encryption_rule") {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted OSS bucket (missing server_side_encryption_rule block).", resourceBlock.FullName())
				return
			}

			applyBlock := resourceBlock.GetBlock("server_side_encryption_rule")
			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted OSS bucket (missing sse_algorithm attribute).", resourceBlock.FullName()).WithBlock(applyBlock)
			}

		},
	})
}
