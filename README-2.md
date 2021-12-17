The new tests are added in the internal/app/tfsec/rules/alicloud/ folder.

When a new service is tested, add it to the internal/app/tfsec/rules/init.go file.

Add the tests to the example/main.tf file.

Relaunch tests:

go run ./cmd/tfsec
