package vpc

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
		LegacyID:  "ALI018",
		Service:   "vpc",
		ShortCode: "add-description-to-security-group",
		Documentation: rule.RuleDocumentation{
			Summary:    "Missing description for security group/security group rule.",
			Impact:     "Descriptions provide context for the firewall rule reasons",
			Resolution: "Add descriptions for all security groups and rules",
			Explanation: `
Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.
`,
			BadExample: []string{`
resource "alicloud_vpc" "bad_example" {
	vpc_name   = "my_vpc"
	cidr_block = "172.16.0.0/12"
}

resource "alicloud_security_group" "bad_example" {
  name        = "http"
}

resource "alicloud_security_group_rule" "bad_example" {
	type              = "ingress"
	ip_protocol       = "tcp"
	nic_type          = "internet"
	policy            = "accept"
	port_range        = "80"
	priority          = 1
	security_group_id = alicloud_security_group.bad_example.id
	cidr_ip           = [alicloud_vpc.bad_example.cidr_block]
}
`},
			GoodExample: []string{`
resource "alicloud_vpc" "good_example" {
	vpc_name   = "my_vpc"
	cidr_block = "172.16.0.0/12"
}

resource "alicloud_security_group" "good_example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"
}

resource "alicloud_security_group_rule" "bad_example" {
	type              = "ingress"
	ip_protocol       = "tcp"
	nic_type          = "internet"
	policy            = "accept"
	port_range        = "80"
	priority          = 1
	security_group_id = alicloud_security_group.good_example.id
	cidr_ip           = [alicloud_vpc.good_example.cidr_block]
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group",
				"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule",
			},
		},
		Provider:        provider.AlicloudProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"alicloud_security_group", "alicloud_security_group_rule"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("description") {
				set.AddResult().
					WithDescription("Resource '%s' should include a description for auditing purposes.", resourceBlock.FullName())
				return
			}

			descriptionAttr := resourceBlock.GetAttribute("description")
			if descriptionAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' should include a non-empty description for auditing purposes.", resourceBlock.FullName()).
					WithAttribute(descriptionAttr)
			}

			checkBlockForDescription("ingress", set, resourceBlock)
			checkBlockForDescription("egress", set, resourceBlock)

		},
	})
}

func checkBlockForDescription(direction string, set result.Set, resourceBlock block.Block) {
	blocks := resourceBlock.GetBlocks(direction)
	for _, b := range blocks {
		descriptionBlock := b.GetAttribute("description")
		if descriptionBlock.IsNil() || descriptionBlock.IsEmpty() {
			set.AddResult().
				WithDescription("Resource '%s' has %s without description.", resourceBlock.FullName(), direction).
				WithBlock(b)
		}
	}
}
