package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/api"
	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestNodeHTTPWithLocalTLSClientWithoutInboundAuthorization(t *testing.T) {
	runNodeHTTPAcceptance(t, func(n *node.Node) http.Handler {
		handler, err := server.New(server.Config{NodeID: integrationNode}, n)
		if err != nil {
			t.Fatal(err)
		}
		return handler
	})
}

// No route or response is mocked: the sole transport fault discards one receipt
// after the real B1 handler has run against its real SQLite authority.
func runNodeHTTPAcceptance(t *testing.T, handlerFor func(*node.Node) http.Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	n, err := node.Open(ctx, config(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n != nil {
			if err := n.Close(); err != nil {
				t.Error("close node", err)
			}
		}
	})
	roots, serverCert := transportCertificates(t)
	handler := handlerFor(n)
	var posts atomic.Int32
	lostReceipt := make(chan []byte, 1)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && posts.Add(1) == 1 {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			if recorder.Code != http.StatusAccepted {
				t.Errorf("real handler did not admit before lost ACK: %d %s", recorder.Code, recorder.Body.Bytes())
			}
			lostReceipt <- bytes.Clone(recorder.Body.Bytes())
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack synthetic connection: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		handler.ServeHTTP(w, r)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	client := tlsClient(t, s.URL, roots)
	t.Cleanup(client.Close)

	read := func(path, query string, output any) apiResponse {
		t.Helper()
		response, err := client.Read(ctx, integrationNode, integrationOwner, path, query)
		if err != nil || response.Status != 200 {
			t.Fatalf("read %s: status=%d err=%v body=%s", path, response.Status, err, response.Body)
		}
		if output != nil {
			if err := json.Unmarshal(response.Body, output); err != nil {
				t.Fatal(err)
			}
		}
		return response
	}
	var health hp.HealthReady
	read("health/ready", "", &health)
	if health.Readiness != "blocked" {
		t.Fatal("node without policy advertised ready")
	}
	read("health/live", "", nil)

	initialProjection := readAdmissionProjection(t, ctx, dir)
	recovered, err := client.Command(ctx, integrationNode, integrationOwner, createCommand())
	if err != nil || recovered.Status != http.StatusAccepted || posts.Load() != 1 {
		t.Fatalf("lost ACK was not reconciled with exactly one POST: status=%d err=%v posts=%d", recovered.Status, err, posts.Load())
	}
	var original []byte
	select {
	case original = <-lostReceipt:
	case <-ctx.Done():
		t.Fatal("handler did not produce a durable receipt")
	}
	if err := hp.Validate("receipt", original); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Body, original) {
		t.Fatalf("reconciliation changed the durable receipt: recovered=%s original=%s", recovered.Body, original)
	}
	var status hp.CommandStatus
	statusResponse := read("commands/"+createID, "", &status)
	_, digest, err := node.CanonicalCommand(createCommand())
	if err != nil || status.CanonicalPayloadHash != digest || status.Status != "accepted" {
		t.Fatalf("command lookup does not prove original intent: %+v %v", status, err)
	}
	var rawStatus struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.Unmarshal(statusResponse.Body, &rawStatus); err != nil || !bytes.Equal(rawStatus.Receipt, original) {
		t.Fatal("command lookup rewrote durable receipt bytes", err)
	}
	beforeReplay := readAdmissionProjection(t, ctx, dir)
	assertOneCreatedDialog(t, initialProjection, beforeReplay)
	replayed, err := client.Command(ctx, integrationNode, integrationOwner, createCommand())
	if err != nil || replayed.Status != 200 || !bytes.Equal(replayed.Body, original) || posts.Load() != 2 {
		t.Fatalf("explicit replay did not return original receipt: status=%d err=%v posts=%d", replayed.Status, err, posts.Load())
	}
	if !reflect.DeepEqual(beforeReplay, readAdmissionProjection(t, ctx, dir)) {
		t.Fatal("HTTP replay mutated durable state, dialogs, commands, or events")
	}
	var refs hp.DialogCreateReferences
	if err := json.Unmarshal(status.Receipt.References, &refs); err != nil {
		t.Fatal(err)
	}

	var before hp.Snapshot
	read("snapshot", "", &before)
	streamCtx, streamCancel := context.WithCancel(ctx)
	stream, err := client.OpenEvents(streamCtx, integrationNode, integrationOwner, before.LastEventSeq)
	if err != nil {
		streamCancel()
		t.Fatal("open replay stream", err)
	}
	defer streamCancel()
	defer func() {
		if stream != nil {
			if err := stream.Close(); err != nil {
				t.Error("close stream", err)
			}
		}
	}()
	text := "Сохранить <>& 😀e\u0301\u2028\u2029"
	command := messageCommand(t, "10000000-0000-4000-8000-000000000021", refs.DialogID, text, 1)
	admitted, err := client.Command(ctx, integrationNode, integrationOwner, command)
	if err != nil || admitted.Status != 202 {
		t.Fatalf("enqueue through private TLS: status=%d err=%v body=%s", admitted.Status, err, admitted.Body)
	}
	var after hp.Snapshot
	read("snapshot", "", &after)
	if after.Node.PendingCount != 1 || len(after.PendingQueue) != 1 || after.LastEventSeq <= before.LastEventSeq || after.ActiveAttempt != nil {
		t.Fatal("blocked node snapshot lost queued work or invented execution")
	}
	for seq := before.LastEventSeq + 1; seq <= after.LastEventSeq; seq++ {
		raw, err := stream.Next()
		if err != nil {
			t.Fatalf("SSE lost committed seq %d: %v", seq, err)
		}
		var event hp.EventEnvelope
		if err := json.Unmarshal(raw, &event); err != nil || event.Seq != seq || event.Epoch != after.Epoch || event.NodeID != integrationNode {
			t.Fatalf("SSE scope/order at %d: %+v %v", seq, event, err)
		}
	}
	streamCloseErr := stream.Close()
	stream = nil
	streamCancel()
	if streamCloseErr != nil {
		t.Fatal("close stream", streamCloseErr)
	}
	var history struct {
		DialogID string               `json:"dialogId"`
		Items    []hp.UserHistoryItem `json:"items"`
	}
	read("dialogs/"+refs.DialogID+"/messages", "limit=1", &history)
	if history.DialogID != refs.DialogID || len(history.Items) != 1 || history.Items[0].Text != text || history.Items[0].RequestID != after.PendingQueue[0].RequestID {
		t.Fatal("history and atomic queue disagree")
	}
	var requests hp.Page[hp.Request]
	read("requests", "state=queued&limit=1", &requests)
	if len(requests.Items) != 1 || requests.Items[0].RequestID != after.PendingQueue[0].RequestID {
		t.Fatal("scoped requests page lost admitted request")
	}
	response, err := client.Read(ctx, integrationNode, integrationOwner, "commands/10000000-0000-4000-8000-000000000099", "")
	if err != nil || response.Status != http.StatusNotFound || hp.Validate("error", response.Body) != nil {
		t.Fatalf("unknown command lookup: status=%d err=%v", response.Status, err)
	}
	// Disconnecting the browser-side stream must not consume or cancel the queue.
	var disconnected hp.Snapshot
	read("snapshot", "", &disconnected)
	if disconnected.Node.PendingCount != 1 || disconnected.LastEventSeq != after.LastEventSeq || posts.Load() != 3 {
		t.Fatal("stream disconnect changed execution or resent a command")
	}
}

func transportCertificates(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"synthetic-" + strconv.FormatInt(serial, 10) + ".invalid"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		d, err := x509.CreateCertificate(rand.Reader, cert, parsed, p, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{d}, PrivateKey: k}
	}
	return roots, leaf(2, x509.ExtKeyUsageServerAuth)
}

func tlsClient(t *testing.T, serverURL string, roots *x509.CertPool) *testAPIClient {
	t.Helper()
	return newTestAPIClient(serverURL, integrationNode, roots)
}
