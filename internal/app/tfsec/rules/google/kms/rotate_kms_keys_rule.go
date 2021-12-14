package kms
 
 // ATTENTION!
 // This rule was autogenerated!
 // Before making changes, consider updating the generator.
 
 import (
 	"strconv"
 
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
 		Service:   "kms",
 		ShortCode: "rotate-kms-keys",
 		Documentation: rule.RuleDocumentation{
 			Summary:     "KMS keys should be rotated at least every 90 days",
 			Explanation: `Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.`,
 			Impact:      "Exposure is greater if the same keys are used over a long period",
 			Resolution:  "Set key rotation period to 90 days",
 			BadExample: []string{`
 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "15552000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 `},
 			GoodExample: []string{`
 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "7776000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 `},
 			Links: []string{
 				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period",
 			},
 		},
 		RequiredTypes: []string{
 			"resource",
 		},
 		RequiredLabels: []string{
 			"google_kms_crypto_key",
 		},
 		DefaultSeverity: severity.High,
 		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
 			rotationAttr := resourceBlock.GetAttribute("rotation_period")
 			if rotationAttr.IsNil() || (rotationAttr.IsResolvable() && rotationAttr.IsEmpty()) {
 				set.AddResult().
 					WithDescription("Resource '%s' does not have key rotation enabled.", resourceBlock)
 				return
 			}
 			if !rotationAttr.IsResolvable() || !rotationAttr.IsString() {
 				return
 			}
 
 			rotationStr := rotationAttr.Value().AsString()
 			if rotationStr[len(rotationStr)-1:] != "s" {
 				return
 			}
 			seconds, err := strconv.Atoi(rotationStr[:len(rotationStr)-1])
 			if err != nil {
 				return
 			}
 			if seconds > 7776000 {
 				set.AddResult().
 					WithDescription("Resource '%s' has a key rotation of greater than 90 days.", resourceBlock)
 			}
 		},
 	})
 }
