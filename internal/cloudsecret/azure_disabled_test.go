//go:build statekit_no_sdk_azure || statekit_no_sdks

package cloudsecret

import (
	"context"
	"errors"
	"testing"
)

func TestAzureAdapterUnavailableWhenOptedOutAtBuildTime(t *testing.T) {
	if AzureAvailable() {
		t.Fatal("Azure SDK adapter must be absent when its opt-out tag is set")
	}
	vault := Source{Provider: "azure", Backend: "keyvault", Region: "prod-vault", Resource: "db-password"}
	if payload, err := FetchAzureKeyVault(context.Background(), vault); !errors.Is(err, ErrUnsupported) || payload != nil {
		t.Fatalf("disabled Key Vault adapter did not fail closed, got %v", err)
	}
	setting := Source{Provider: "azure", Backend: "appconfiguration", Region: "prod-store", Resource: "app.setting", Label: "production"}
	if payload, err := FetchAzureAppConfiguration(context.Background(), setting); !errors.Is(err, ErrUnsupported) || payload != nil {
		t.Fatalf("disabled App Configuration adapter did not fail closed, got %v", err)
	}
	// Typed validation still runs and rejects before any credential or
	// network concept exists in the disabled build.
	invalid := Source{Provider: "azure", Backend: "keyvault", Region: "prod.vault.example", Resource: "db"}
	if payload, err := FetchAzureKeyVault(context.Background(), invalid); !errors.Is(err, ErrInvalidSource) || payload != nil {
		t.Fatalf("disabled adapter must still reject invalid sources first, got %v", err)
	}
}
