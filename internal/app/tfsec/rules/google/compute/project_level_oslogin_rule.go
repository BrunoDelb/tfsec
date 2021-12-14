package compute
 
 // ATTENTION!
 // This rule was autogenerated!
 // Before making changes, consider updating the generator.
 
 import (
 	"github.com/aquasecurity/defsec/provider"
 	"github.com/aquasecurity/defsec/result"
 	"github.com/aquasecurity/defsec/severity"
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
 	"github.com/aquasecurity/tfsec/pkg/rule"
 	"github.com/zclconf/go-cty/cty"
 )
 
 func init() {
 	scanner.RegisterCheckRule(rule.Rule{
 		Provider:  provider.GoogleProvider,
 		Service:   "compute",
 		ShortCode: "project-level-oslogin",
 		Documentation: rule.RuleDocumentation{
 			Summary:     "OS Login should be enabled at project level",
 			Explanation: `OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.`,
 			Impact:      "Access via SSH key cannot be revoked automatically when an IAM user is removed.",
 			Resolution:  "Enable OS Login at project level",
 			BadExample: []string{`
 resource "google_compute_project_metadata" "default" {
   metadata = {
 	enable-oslogin = false
   }
 }
 `},
 			GoodExample: []string{`
 resource "google_compute_project_metadata" "default" {
   metadata = {
     enable-oslogin = true
   }
 }
 `},
 			Links: []string{
 				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#",
 			},
 		},
 		RequiredTypes: []string{
 			"resource",
 		},
 		RequiredLabels: []string{
 			"google_compute_project_metadata",
 		},
 		DefaultSeverity: severity.Medium,
 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
 			metadataAttr := resourceBlock.GetAttribute("metadata")
 			val := metadataAttr.MapValue("enable-oslogin")
 			if val.Type() == cty.NilType {
 				set.AddResult().
 					WithDescription("Resource'%s' has OS Login disabled by default", resourceBlock)
 				return
 			}
 			if val.Type() == cty.Bool && val.False() {
 				set.AddResult().
 					WithDescription("Resource'%s' has OS Login explicitly disabled", resourceBlock).
 					WithAttribute("")
 				return
 			}
 		},
 	})
 }
