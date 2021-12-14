package bigquery
 
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
 )
 
 func init() {
 	scanner.RegisterCheckRule(rule.Rule{
 		Provider:  provider.GoogleProvider,
 		Service:   "bigquery",
 		ShortCode: "no-public-access",
 		Documentation: rule.RuleDocumentation{
 			Summary:     "BigQuery datasets should only be accessible within the organisation",
 			Explanation: `Using 'allAuthenticatedUsers' provides any GCP user - even those outside of your organisation - access to your BigQuery dataset.`,
 			Impact:      "Exposure of sensitive data to the public iniernet",
 			Resolution:  "Configure access permissions with higher granularity",
 			BadExample: []string{`
 resource "google_bigquery_dataset" "bad_example" {
   dataset_id                  = "example_dataset"
   friendly_name               = "test"
   description                 = "This is a test description"
   location                    = "EU"
   default_table_expiration_ms = 3600000
 
   labels = {
     env = "default"
   }
 
   access {
     role          = "OWNER"
     special_group = "allAuthenticatedUsers"
   }
 
   access {
     role   = "READER"
     domain = "hashicorp.com"
   }
 }
 
 `},
 			GoodExample: []string{`
 resource "google_bigquery_dataset" "good_example" {
   dataset_id                  = "example_dataset"
   friendly_name               = "test"
   description                 = "This is a test description"
   location                    = "EU"
   default_table_expiration_ms = 3600000
 
   labels = {
     env = "default"
   }
 
   access {
     role          = "OWNER"
     user_by_email = google_service_account.bqowner.email
   }
 
   access {
     role   = "READER"
     domain = "hashicorp.com"
   }
 }
 
 resource "google_service_account" "bqowner" {
   account_id = "bqowner"
 }
 `},
 			Links: []string{
 				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_dataset#special_group",
 			},
 		},
 		RequiredTypes: []string{
 			"resource",
 		},
 		RequiredLabels: []string{
 			"google_bigquery_dataset",
 		},
 		DefaultSeverity: severity.Critical,
 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
 			if specialGroupAttr := resourceBlock.GetBlock("access").GetAttribute("special_group"); specialGroupAttr.Equals("allAuthenticatedUsers") {
 				set.AddResult().
 					WithDescription("Resource '%s' has access.special_group set to allAuthenticatedUsers", resourceBlock.FullName()).
 					WithAttribute("")
 			}
 		},
 	})
 }
