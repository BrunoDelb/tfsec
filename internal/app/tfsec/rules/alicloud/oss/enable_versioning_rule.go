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
		LegacyID:  "ALI077",
		Service:   "oss",
		ShortCode: "enable-versioning",
		Documentation: rule.RuleDocumentation{
			Summary:    "OSS Data should be versioned",
			Impact:     "Deleted or modified data would not be recoverable",
			Resolution: "Enable versioning to protect against accidental/malicious removal or modification",
			Explanation: `
Versioning in Alibaba Cloud OSS is a means of keeping multiple variants of an object in the same bucket. 
You can use the OSS Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.
`,
			BadExample: []string{`
resource "alicloud_oss_bucket" "bad_example" {

}
`},
			GoodExample: []string{`
resource "alicloud_oss_bucket" "good_example" {

	versioning {
		status = "Enabled"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#versioning",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_oss_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("versioning") {
				set.AddResult().
					WithDescription("Resource '%s' does not have versioning enabled", resourceBlock.FullName())
				return
			}

			versioningBlock := resourceBlock.GetBlock("versioning")
			if versioningBlock.HasChild("status") && versioningBlock.GetAttribute("status").Equals("Enabled") {
				set.AddResult().
					WithDescription("Resource '%s' has versioning block but is disabled", resourceBlock.FullName()).WithBlock(versioningBlock)
			}
		},
	})
}
