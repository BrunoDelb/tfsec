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
		LegacyID:  "ALI039",
		Service:   "ram",
		ShortCode: "set-minimum-password-length",
		Documentation: rule.RuleDocumentation{
			Summary:    "RAM Password policy should have minimum password length of 14 or more characters.",
			Impact:     "Short, simple passwords are easier to compromise",
			Resolution: "Enforce longer, more complex passwords in the policy",
			Explanation: `RAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.`,
			BadExample: []string{`
resource "alicloud_ram_account_password_policy" "bad_example" {
	# ...
	# minimum_password_length not set
	# ...
}
`},
			GoodExample: []string{`
resource "alicloud_ram_account_password_policy" "good_example" {
	# ...
	minimum_password_length = 14
	# ...
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_ram_account_password_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if attr := resourceBlock.GetAttribute("minimum_password_length"); attr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not have a minimum password length set.", resourceBlock.FullName())
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 14 {
					set.AddResult().
						WithDescription("Resource '%s' has a minimum password length which is less than 14 characters.", resourceBlock.FullName())
				}
			}
		},
	})
}
