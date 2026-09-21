package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestArtifactThroughPrivateAPIClientRejectsLostOrCorruptedBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	dir := t.TempDir()
	cfg := config(dir)
	cfg.Adapter = &queuedAdapter{fixture.NewAdapter()}
	cfg.Policies = fixture.NewPolicySource()
	n, err := node.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n != nil {
			if err := n.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), 202, createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	command := messageCommand(t, "10000000-0000-4000-8000-000000004001", dialog.DialogID, "synthetic artifact producer", 1)
	receipt(t, n.SubmitCommand(ctx, trusted(), command), 202, command)
	dispatch, err := n.DispatchNext(ctx)
	if err != nil || dispatch.Outcome != "dispatching" {
		t.Fatal(dispatch, err)
	}
	running := waitRunning(t, ctx, n, dispatch.AttemptID)
	want := bytes.Repeat([]byte("Синтетический safe output <>& 😀\n"), 4096)
	if len(want) <= 64<<10 {
		t.Fatal("fixture must exercise content above inline limit")
	}
	input := bytes.Clone(want)
	metadata, err := n.ArtifactSink().StoreArtifact(ctx, node.ArtifactInput{Attempt: harnessadapter.AttemptRef{NodeID: integrationNode, DialogID: dialog.DialogID, RequestID: dispatch.RequestID, AttemptID: dispatch.AttemptID, Generation: running.ActiveAttempt.Generation}, Name: "synthetic output.txt", MediaType: "text/plain; charset=utf-8", Redaction: "none", Disposition: "attachment"}, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] ^= 0xff
	sum := sha256.Sum256(want)
	if metadata.SizeBytes != int64(len(want)) || metadata.SHA256 != hex.EncodeToString(sum[:]) || metadata.DialogID != dialog.DialogID || metadata.AttemptID != dispatch.AttemptID {
		t.Fatal("stored artifact metadata lost bytes or ownership")
	}

	roots, serverCert := transportCertificates(t)
	handler, err := server.New(server.Config{NodeID: integrationNode}, n)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	client := tlsClient(t, s.URL, roots)
	t.Cleanup(client.Close)
	full, err := client.Artifact(ctx, integrationNode, integrationOwner, metadata.ArtifactID, "")
	if err != nil || full.Status != 200 || !bytes.Equal(full.Body, want) || !reflect.DeepEqual(full.Metadata, metadata) {
		t.Fatal("real artifact headers/bytes/metadata failed verification", err)
	}
	part, err := client.Artifact(ctx, integrationNode, integrationOwner, metadata.ArtifactID, "bytes=5-23")
	if err != nil || part.Status != 206 || !bytes.Equal(part.Body, want[5:24]) || part.ContentRange != fmt.Sprintf("bytes 5-23/%d", len(want)) {
		t.Fatal("verified HTTP range failed", err)
	}
	_, err = client.Artifact(ctx, integrationNode, integrationOwner, metadata.ArtifactID, fmt.Sprintf("bytes=%d-", len(want)))
	var rangeFailure *apiFault
	if !errors.As(err, &rangeFailure) || rangeFailure.Status != 416 {
		t.Fatal("invalid HTTP range was not rejected", err)
	}

	artifactPath := filepath.Join(dir, "artifacts", metadata.ArtifactID)
	assertUnavailable := func() {
		t.Helper()
		read, err := client.Read(ctx, integrationNode, integrationOwner, "artifacts/"+metadata.ArtifactID+"/metadata", "")
		if err != nil || read.Status != 503 || hp.Validate("error", read.Body) != nil {
			t.Fatal("lost/corrupt bytes still advertised successful metadata", read.Status, err)
		}
		result, err := client.Artifact(ctx, integrationNode, integrationOwner, metadata.ArtifactID, "")
		var failure *apiFault
		if !errors.As(err, &failure) || failure.Status != 503 || failure.Code != "not_durable" || len(result.Body) != 0 {
			t.Fatal("lost/corrupt bytes reached private API client", err)
		}
	}
	// Keep the size identical so this specifically exercises hash integrity.
	corrupt := bytes.Clone(want)
	corrupt[len(corrupt)-1] ^= 1
	if err := os.WriteFile(artifactPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	assertUnavailable()
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	assertUnavailable()
	closeErr := n.Close()
	n = nil
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
