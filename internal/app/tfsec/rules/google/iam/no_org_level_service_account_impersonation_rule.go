package iam

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{
			`
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/iam.serviceAccountUser"
 }
 `,
			`
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/iam.serviceAccountTokenCreator"
 }
 `,
		},
		GoodExample: []string{`
 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/nothingInParticular"
 }
 			`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam",
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_organization_iam_binding", "google_organization_iam_member"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			roleAttr := resourceBlock.GetAttribute("role")
			if !roleAttr.IsString() {
				return
			}
			if roleAttr.IsAny("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
				set.AddResult().
					WithDescription("Resource grants service account access to a user at organization level.", ?)
			}

			return results
		},
	})
}
