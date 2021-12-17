package ecs

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
		LegacyID:  "ALI062",
		Service:   "ecs",
		ShortCode: "no-secrets-in-user-data",
		Documentation: rule.RuleDocumentation{
			Summary:    "User data for ECS instances must not contain sensitive AliCloud keys",
			Impact:     "User data is visible through the Alibaba Cloud console",
			Resolution: "Remove sensitive data from the ECS instance user-data",
			Explanation: `
ECS instance data is used to pass start up information into the ECS instance. This userdata must not contain access key credentials. Instead use an RAM Instance Profile assigned to the instance to grant access to other Alibaba Cloud Services.
`,
			BadExample: []string{`
resource "alicloud_instance" "bad_example" {

  image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
  instance_type = "ecs.n4.large"

  user_data = <<EOF
export ALICLOUD_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
export ALICLOUD_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export ALICLOUD_REGION=us-west-2 
EOF
}
`},
			GoodExample: []string{`
resource "alicloud_instance" "good_example" {
  image_id      = "ubuntu_18_04_64_20G_alibase_20190624.vhd"
  instance_type = "ecs.n4.large"

  ram_name = alicloud_ram_role.good_profile.arn

  user_data = <<EOF
  export GREETING=hello
EOF
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/instance#user_data",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_instance"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("user_data") {
				return
			}

			userDataAttr := resourceBlock.GetAttribute("user_data")
			if userDataAttr.Contains("ALICLOUD_ACCESS_KEY", block.IgnoreCase) &&
				userDataAttr.RegexMatches("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}") {
				set.AddResult().
					WithDescription("Resource '%s' has userdata with access key id defined.", resourceBlock.FullName()).
					WithAttribute(userDataAttr)
			}

			if userDataAttr.Contains("ALICLOUD_SECRET_KEY", block.IgnoreCase) &&
				userDataAttr.RegexMatches("(?i)alicloud_secre.+[=:]\\s{0,}[A-Za-z0-9\\/+=]{40}.?") {
				set.AddResult().
					WithDescription("Resource '%s' has userdata with access secret key defined.", resourceBlock.FullName()).
					WithAttribute(userDataAttr)
			}
		},
	})
}
