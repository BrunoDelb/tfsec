package ram

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "ALI038",
		Service:   "ram",
		ShortCode: "set-max-password-age",
		Documentation: rule.RuleDocumentation{
			Summary:    "RAM Password policy should have expiry less than or equal to 90 days.",
			Impact:     "Long life password increase the likelihood of a password eventually being compromised",
			Resolution: "Limit the password duration with an expiry in the policy",
			Explanation: `RAM account password policies should have a maximum age specified. 
		
The account password policy should be set to expire passwords after 90 days or less.`,
			BadExample: []string{`
resource "alicloud_ram_account_password_policy" "bad_example" {
	# ...
	# max_password_age not set
	# ...
}`},
			GoodExample: []string{`
resource "alicloud_ram_account_password_policy" "good_example" {
	# ...
	max_password_age = 90
	# ...
}`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_ram_account_password_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if attr := resourceBlock.GetAttribute("max_password_age"); attr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have a max password age set.", resourceBlock.FullName())
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value > 90 {
					set.AddResult().
						WithDescription("Resource '%s' has high password age.", resourceBlock.FullName()).
						WithAttribute(attr)
				}
			}
		},
	})
}
