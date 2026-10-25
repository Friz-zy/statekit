package cloudsecret

import (
	"strings"
	"testing"
)

// These validation tests are build-tag independent: the typed Azure source
// contract must hold identically in SDK-enabled and disabled builds.

func TestValidateSourceAzureKeyVaultContract(t *testing.T) {
	valid := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	if err := ValidateSource(valid); err != nil {
		t.Fatalf("valid Key Vault source rejected: %v", err)
	}
	pinned := valid
	pinned.VersionID = "0123456789abcdef0123456789abcdef"
	if err := ValidateSource(pinned); err != nil {
		t.Fatalf("valid pinned Key Vault version rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		source Source
		want   error
	}{
		// The vault name grammar is the endpoint policy: dots (private
		// endpoints, custom hosts), colons (ports), and uppercase forms are
		// unreachable, so only <name>.vault.azure.net can be dialed.
		{name: "dot-in-vault-name", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod.vault.example", Resource: "db"}, want: ErrInvalidSource},
		{name: "uppercase-vault-name", source: Source{Provider: "azure", Backend: "keyvault", Region: "ProdVault", Resource: "db"}, want: ErrInvalidSource},
		{name: "vault-name-too-short", source: Source{Provider: "azure", Backend: "keyvault", Region: "pr", Resource: "db"}, want: ErrInvalidSource},
		{name: "vault-name-too-long", source: Source{Provider: "azure", Backend: "keyvault", Region: "v" + strings.Repeat("ault-name", 3), Resource: "db"}, want: ErrInvalidSource},
		{name: "vault-name-leading-dash", source: Source{Provider: "azure", Backend: "keyvault", Region: "-prod-vault", Resource: "db"}, want: ErrInvalidSource},
		{name: "vault-name-trailing-dash", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault-", Resource: "db"}, want: ErrInvalidSource},
		{name: "vault-name-double-dash", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod--vault", Resource: "db"}, want: ErrInvalidSource},
		{name: "secret-name-slash", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db/password"}, want: ErrInvalidSource},
		{name: "secret-name-empty", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: ""}, want: ErrInvalidSource},
		{name: "secret-name-too-long", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: strings.Repeat("n", 128)}, want: ErrInvalidSource},
		{name: "secret-name-space", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db password"}, want: ErrInvalidSource},
		{name: "version-too-short", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", VersionID: strings.Repeat("a", 31)}, want: ErrInvalidSource},
		{name: "version-too-long", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", VersionID: strings.Repeat("a", 33)}, want: ErrInvalidSource},
		{name: "version-uppercase-hex", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", VersionID: strings.Repeat("A", 32)}, want: ErrInvalidSource},
		{name: "version-non-hex", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", VersionID: strings.Repeat("z", 32)}, want: ErrInvalidSource},
		{name: "alias-rejected", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", VersionAlias: "latest"}, want: ErrInvalidSource},
		{name: "unknown-backend", source: Source{Provider: "azure", Backend: "managedhsm", Region: "prod-vault", Resource: "db"}, want: ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSource(tc.source)
			if err != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateSourceAzureAppConfigurationContract(t *testing.T) {
	valid := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	if err := ValidateSource(valid); err != nil {
		t.Fatalf("valid App Configuration source rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		source Source
		want   error
	}{
		// The label is the explicit first-class setting-version selector:
		// mandatory, grammar-bound, and the only selector this backend takes.
		{name: "missing-label", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting"}, want: ErrInvalidSource},
		{name: "empty-label", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: ""}, want: ErrInvalidSource},
		{name: "wildcard-label", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "*"}, want: ErrInvalidSource},
		{name: "label-with-space", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "prod uction"}, want: ErrInvalidSource},
		{name: "label-leading-dot", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: ".production"}, want: ErrInvalidSource},
		{name: "label-as-version-alias-rejected", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production", VersionAlias: "production"}, want: ErrInvalidSource},
		{name: "version-alias-without-label-rejected", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", VersionAlias: "production"}, want: ErrInvalidSource},
		{name: "version-id-rejected", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production", VersionID: "1"}, want: ErrInvalidSource},
		{name: "dot-in-store-name", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod.store.example", Resource: "app.setting", Label: "production"}, want: ErrInvalidSource},
		{name: "store-name-too-short", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod", Resource: "app.setting", Label: "production"}, want: ErrInvalidSource},
		{name: "store-name-too-long", source: Source{Provider: "azure", Backend: "appconfiguration", Region: strings.Repeat("s", 51), Resource: "app.setting", Label: "production"}, want: ErrInvalidSource},
		{name: "key-leading-dot", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: ".app.setting", Label: "production"}, want: ErrInvalidSource},
		{name: "key-trailing-dot", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting.", Label: "production"}, want: ErrInvalidSource},
		{name: "key-slash", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app/setting", Label: "production"}, want: ErrInvalidSource},
		{name: "key-too-long", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: strings.Repeat("k", 256), Label: "production"}, want: ErrInvalidSource},
		{name: "label-too-long", source: Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: strings.Repeat("l", 256)}, want: ErrInvalidSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSource(tc.source)
			if err != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestValidateSourceLabelRouting keeps the label selector exclusive: only
// azure appconfiguration accepts it, and every other provider and backend
// rejects a labeled source before any credential or fetch activity.
func TestValidateSourceLabelRouting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source Source
	}{
		{name: "label on key vault", source: Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db", Label: "production"}},
		{name: "label on aws secretsmanager", source: Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: "db", Label: "production"}},
		{name: "label on gcp secretmanager", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", Label: "production"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSource(tc.source); err != ErrInvalidSource {
				t.Fatalf("labeled non-appconfig source must be invalid, got %v", err)
			}
		})
	}
	if err := ValidateParameterSource(Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/p/locations/global/parameters/c", Label: "production"}); err != ErrInvalidSource {
		t.Fatalf("labeled parameter source must be invalid, got %v", err)
	}
}

// TestAzureSourceIdentitySeparateFromComposedValidation pins the AZ-03
// contract: a secret:// URI carries the App Configuration identity alone
// and parses without a label; ValidateSource then rejects the incomplete
// identity and accepts it once an explicit label is composed in.
func TestAzureSourceIdentitySeparateFromComposedValidation(t *testing.T) {
	parsed, err := ParseSourceURI("secret://azure/appconfiguration/prod-store/app.setting")
	if err != nil {
		t.Fatalf("appconfig identity URI must parse without a label: %v", err)
	}
	if err := ValidateSourceIdentity(parsed); err != nil {
		t.Fatalf("identity grammar must hold for the parsed URI: %v", err)
	}
	if err := ValidateSource(parsed); err != ErrInvalidSource {
		t.Fatalf("composed validation must require the label, got %v", err)
	}
	parsed.Label = "production"
	if err := ValidateSource(parsed); err != nil {
		t.Fatalf("identity plus explicit label must validate exactly once: %v", err)
	}
}

func TestParseSourceURIAzureForms(t *testing.T) {
	keyVault, err := ParseSourceURI("secret://azure/keyvault/prod-vault/db-password")
	if err != nil || keyVault.Provider != "azure" || keyVault.Backend != "keyvault" || keyVault.Region != "prod-vault" || keyVault.Resource != "db-password" {
		t.Fatalf("canonical Azure Key Vault URI rejected: %v", err)
	}
	setting, err := ParseSourceURI("secret://azure/appconfiguration/prod-store/app.setting")
	if err != nil || setting.Resource != "app.setting" {
		t.Fatalf("canonical Azure App Configuration identity URI rejected: %v", err)
	}
	if err := ValidateSource(setting); err != ErrInvalidSource {
		t.Fatalf("appconfig URI without an explicit label must stay incomplete, got %v", err)
	}
	for _, uri := range []string{
		"secret://azure/keyvault/ProdVault/db",
		"secret://azure/keyvault/prod.vault.example/db",
		"secret://azure/keyvault/prod-vault/db%2Fextra",
		"secret://azure/managedhsm/prod-vault/db",
	} {
		if _, err := ParseSourceURI(uri); err == nil {
			t.Fatalf("off-contract Azure URI %q was accepted", uri)
		}
	}
}
