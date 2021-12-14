package neptune
 
 // ATTENTION!
 // This rule was autogenerated!
 // Before making changes, consider updating the generator.
 
 // generator-locked
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
 		Provider:  provider.AWSProvider,
 		Service:   "neptune",
 		ShortCode: "enable-log-export",
 		Documentation: rule.RuleDocumentation{
 			Summary:     "Nepture logs export should be enabled",
 			Explanation: `Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.`,
 			Impact:      "Limited visibility of audit trail for changes to Neptune",
 			Resolution:  "Enable export logs",
 			BadExample: []string{`
 resource "aws_neptune_cluster" "bad_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = []
 }
 `},
 			GoodExample: []string{`
 resource "aws_neptune_cluster" "good_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = ["audit"]
 }
 `},
 			Links: []string{
 				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#enable_cloudwatch_logs_exports",
 			},
 		},
 		RequiredTypes: []string{
 			"resource",
 		},
 		RequiredLabels: []string{
 			"aws_neptune_cluster",
 		},
 		DefaultSeverity: severity.Medium,
 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
 			if enableCloudwatchLogsExportsAttr := resourceBlock.GetAttribute("enable_cloudwatch_logs_exports"); enableCloudwatchLogsExportsAttr.IsNil() { // alert on use of default value
 				set.AddResult().
 					WithDescription("Resource '%s' uses default value for enable_cloudwatch_logs_exports", resourceBlock.FullName())
 			} else if enableCloudwatchLogsExportsAttr.NotContains("audit") {
 				set.AddResult().
 					WithDescription("Resource '%s' should have audit in enable_cloudwatch_logs_exports", resourceBlock.FullName()).
 					WithAttribute("")
 			}
 		},
 	})
 }
