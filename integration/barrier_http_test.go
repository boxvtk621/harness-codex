package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestBarrierRejectionAndExactReadbackThroughRealClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := t.TempDir()
	n, err := node.Open(ctx, config(path))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	created := receipt(t, n.SubmitCommand(ctx, trusted(), createCommand()), http.StatusAccepted, createCommand())
	var dialog hp.DialogCreateReferences
	if err := json.Unmarshal(created.References, &dialog); err != nil {
		t.Fatal(err)
	}
	snapshot := queueSnapshot(t, ctx, n)
	holdRequest, err := json.Marshal(harnessbarrier.InstallRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID,
		OperationID: "http-dialog-hold", NodeID: integrationNode, ExpectedEpoch: snapshot.Epoch, BindingGeneration: 1,
		Scope: harnessbarrier.Scope{Kind: "dialog", DialogID: dialog.DialogID}, ExpectedScopeRevision: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	hold := n.InstallHold(ctx, node.OperatorTrustContext{PeerVerified: true, ActorID: integrationOwner, TransportNodeID: integrationNode}, holdRequest)
	if hold.HTTPStatus != http.StatusCreated || harnessbarrier.Validate("holdReceipt", hold.Body) != nil {
		t.Fatalf("install hold: status=%d body=%s", hold.HTTPStatus, hold.Body)
	}

	roots, serverCert, clientCert := transportCertificates(t)
	pin := sha256.Sum256(clientCert.Certificate[0])
	handler, err := server.New(server.Config{NodeID: integrationNode, GatewayCertificateSHA256: hex.EncodeToString(pin[:])}, n)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(handler)
	httpServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	httpServer.StartTLS()
	defer httpServer.Close()
	client := signedClient(t, httpServer.URL, roots, serverCert, clientCert)
	defer client.Close()

	late := messageCommand(t, "55000000-0000-4000-8000-000000000001", dialog.DialogID, "delayed forwarded submit", 1)
	rejected, err := client.Command(ctx, integrationNode, integrationOwner, late)
	if err != nil || rejected.Status != http.StatusConflict || harnessbarrier.Validate("rejectionReceipt", rejected.Body) != nil {
		t.Fatalf("client did not accept versioned rejection: status=%d err=%v body=%s", rejected.Status, err, rejected.Body)
	}
	replayed, err := client.Command(ctx, integrationNode, integrationOwner, late)
	if err != nil || replayed.Status != http.StatusConflict || !bytes.Equal(replayed.Body, rejected.Body) {
		t.Fatalf("HTTP rejection replay changed: status=%d err=%v body=%s", replayed.Status, err, replayed.Body)
	}
	readback, err := client.Read(ctx, integrationNode, integrationOwner, "commands/55000000-0000-4000-8000-000000000001", "")
	if err != nil || readback.Status != http.StatusConflict || !bytes.Equal(readback.Body, rejected.Body) {
		t.Fatalf("HTTP rejection readback changed: status=%d err=%v body=%s", readback.Status, err, readback.Body)
	}
	if after := queueSnapshot(t, ctx, n); after.StateVersion != snapshot.StateVersion || after.LastEventSeq != snapshot.LastEventSeq || after.Node.PendingCount != 0 {
		t.Fatalf("HTTP rejection changed checkpoint: before=%+v after=%+v", snapshot, after)
	}
}
