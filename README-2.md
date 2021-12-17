Les nouveaux tests sont ajoutés au répertoire internal/app/tfsec/rules/alicloud/

Quand un nouveau service est testé, l'ajouter au fichier internal/app/tfsec/rules/init.go

Ajouter les tests au fichier example/main.tf

Relancer les tests :

go run ./cmd/tfsec
