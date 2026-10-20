//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

func TestCloudSecretHelpDocumentsMutableLatestDefault(t *testing.T) {
	if !strings.Contains(usageText, "GCP Secret Manager reads use mutable latest when neither --version-id nor") ||
		!strings.Contains(usageText, "--version-alias is supplied. Set a numeric --version-id when stable content is needed.") {
		t.Fatal("GCP Secret Manager help does not document the mutable latest default and numeric version selection")
	}
}

func TestCloudSecretGetRoutesGCPURIAndStructuredSourcesToSelectedSinks(t *testing.T) {
	calls := 0
	app := NewApp("test-version", nil)
	app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "gcp" || source.Backend != "secretmanager" || source.Region != "global" || source.Resource != "projects/project-123/secrets/db" || source.VersionID != "14" || source.VersionAlias != "" {
			t.Fatal("GCP URI request did not map to the exact structured source and numeric version")
		}
		return []byte(`{"credentials":{"token":"synthetic"}}`), nil
	}
	code, stdout, stderr := captureCode(t, app, "exec", "cloud.secret.get", "--source-uri", "secret://gcp/secretmanager/global/projects%2Fproject-123%2Fsecrets%2Fdb", "--version-id", "14", "--format", "json", "--key-path", "/credentials/token")
	if code != ExitOK || stdout != `"synthetic"` || stderr != "" || calls != 1 {
		t.Fatal("GCP URI source did not deliver formatted payload to stdout")
	}
	app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "gcp" || source.Backend != "secretmanager" || source.Region != "global" || source.Resource != "projects/project-123/secrets/db" || source.VersionID != "" || source.VersionAlias != "latest" {
			t.Fatal("GCP structured source did not map the explicit latest selector")
		}
		return []byte("synthetic-text"), nil
	}
	code, stdout, stderr = captureCode(t, app, "exec", "cloud.secret.get", "--config", "provider: gcp\nbackend: secretmanager\nregion: global\nresource: projects/project-123/secrets/db\nversion_alias: latest\nformat: text\nsink: stderr\n")
	if code != ExitOK || stdout != "" || stderr != "synthetic-text" || calls != 2 {
		t.Fatal("GCP structured source did not deliver formatted payload to stderr")
	}
	app.secretFetch = func(_ context.Context, source cloudsecret.Source) ([]byte, error) {
		calls++
		if source.Provider != "gcp" || source.Backend != "secretmanager" || source.Region != "global" || source.Resource != "projects/project-123/secrets/db" || source.VersionID != "" || source.VersionAlias != "" {
			t.Fatal("GCP structured source without selector did not preserve default-latest mapping")
		}
		return []byte("synthetic-default"), nil
	}
	code, stdout, stderr = captureCode(t, app, "exec", "cloud.secret.get", "--config", "provider: gcp\nbackend: secretmanager\nregion: global\nresource: projects/project-123/secrets/db\nformat: text\nsink: stdout\n")
	if code != ExitOK || stdout != "synthetic-default" || stderr != "" || calls != 3 {
		t.Fatal("GCP structured source did not preserve default selector and stdout sink")
	}
}
