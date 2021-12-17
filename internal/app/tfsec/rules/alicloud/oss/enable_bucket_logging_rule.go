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
		LegacyID:  "ALI002",
		Service:   "oss",
		ShortCode: "enable-bucket-logging",
		Documentation: rule.RuleDocumentation{
			Summary: "OSS Bucket does not have logging enabled.",
			Explanation: `
Buckets should have logging enabled so that access can be audited. 
`,
			Impact:     "There is no way to determine the access to this bucket",
			Resolution: "Add a logging block to the resource to enable access logging",
			BadExample: []string{`
resource "alicloud_oss_bucket" "bad_example" {

}
`},
			GoodExample: []string{`
resource "alicloud_oss_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#logging",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_oss_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("logging") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logging enabled.", resourceBlock.FullName())
			}
		},
	})
}
