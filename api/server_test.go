package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/api"
	"github.com/boxvtk621/harness-codex/fixture"
	"github.com/boxvtk621/harness-codex/internal/dialogview"
	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/logicaldelete"
	"github.com/boxvtk621/harness-codex/internal/tooltimeline"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
	"github.com/boxvtk621/harness-codex/runtime"
)

const testNodeID = "20000000-0000-4000-8000-000000000001"

type enoughSpace struct{}

func (enoughSpace) Measure(string) (node.SpaceInfo, error) {
	return node.SpaceInfo{FreeBytes: 16 << 30, TotalBytes: 64 << 30}, nil
}

func TestRealTLSCommandsAndReadsWithoutInboundAuthorization(t *testing.T) {
	ca, caKey, caPool := certificateAuthority(t)
	serverCertificate, _ := signedCertificate(t, ca, caKey, "localhost", false)
	authority, err := node.Open(context.Background(), node.Config{
		DataDir: t.TempDir(), NodeID: testNodeID, OwnerID: "1-1", RegistryVersion: 1,
		Adapter: fixture.NewAdapter(), Policies: fixture.NewPolicySource(), Space: enoughSpace{}, ManualDispatchForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	handler, err := server.New(server.Config{NodeID: testNodeID}, authority)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewUnstartedServer(handler)
	endpoint.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS13,
	}
	endpoint.StartTLS()
	defer endpoint.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: caPool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}}}
	operatorClient := client

	identity := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/identity", "", "1-1")
	validateResponse(t, identity, http.StatusOK, "nodeIdentity")
	var expected harnessprotocol.NodeIdentity
	if err := json.Unmarshal(identity[2:], &expected); err != nil {
		t.Fatal(err)
	}
	holdRequest, _ := json.Marshal(harnessbarrier.InstallRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID, OperationID: "server-proof-1",
		NodeID: testNodeID, ExpectedEpoch: expected.IdentityEpoch, BindingGeneration: expected.RegistryVersion,
		Scope: harnessbarrier.Scope{Kind: "node"}, ExpectedScopeRevision: 0,
	})
	wrongRole := request(t, client, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/administration/holds", string(holdRequest), "1-1")
	if status := int(wrongRole[0])<<8 | int(wrongRole[1]); status != http.StatusCreated {
		t.Fatalf("admin request without operator identity status=%d", status)
	}
	holdResponse := request(t, operatorClient, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/administration/holds", string(holdRequest), "1-1")
	if status := int(holdResponse[0])<<8 | int(holdResponse[1]); (status != http.StatusCreated && status != http.StatusOK) || harnessbarrier.Validate("holdReceipt", holdResponse[2:]) != nil {
		t.Fatalf("administrative hold endpoint failed: status=%d body=%s", status, holdResponse[2:])
	}
	var hold harnessbarrier.HoldReceipt
	_ = json.Unmarshal(holdResponse[2:], &hold)
	proofResponse := request(t, operatorClient, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/administration/holds/server-proof-1/proof", "", "1-1")
	if status := int(proofResponse[0])<<8 | int(proofResponse[1]); status != http.StatusOK || harnessbarrier.Validate("quiescenceProof", proofResponse[2:]) != nil {
		t.Fatalf("administrative proof endpoint failed: status=%d body=%s", status, proofResponse[2:])
	}
	releaseRequest, _ := json.Marshal(harnessbarrier.ReleaseRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID, OperationID: hold.OperationID,
		NodeID: hold.NodeID, ExpectedEpoch: hold.Epoch, BindingGeneration: hold.BindingGeneration, Scope: hold.Scope,
		HoldVersion: hold.HoldVersion, ExpectedScopeRevision: hold.ScopeRevision, Action: "release",
	})
	releaseResponse := request(t, operatorClient, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/administration/holds/server-proof-1/release", string(releaseRequest), "1-1")
	if status := int(releaseResponse[0])<<8 | int(releaseResponse[1]); status != http.StatusCreated || harnessbarrier.Validate("releaseReceipt", releaseResponse[2:]) != nil {
		t.Fatalf("administrative release endpoint failed: status=%d body=%s", status, releaseResponse[2:])
	}
	create := `{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000201","kind":"dialog.create","target":{"nodeId":"` + testNodeID + `"},"expected":{"registryVersion":1},"payload":{}}`
	accepted := requestExpected(t, client, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/commands", create, "1-1", &expected)
	validateResponse(t, accepted, http.StatusAccepted, "receipt")
	stale := expected
	stale.IdentityEpoch++
	rejected := requestExpected(t, client, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/commands", create, "1-1", &stale)
	validateResponse(t, rejected, http.StatusConflict, "error")
	status := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/commands/10000000-0000-4000-8000-000000000201", "", "1-1")
	validateResponse(t, status, http.StatusOK, "commandStatus")
	snapshot := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/snapshot", "", "1-1")
	validateResponse(t, snapshot, http.StatusOK, "snapshot")
	ready := request(t, client, http.MethodGet, endpoint.URL+"/health/ready", "", "1-1")
	validateResponse(t, ready, http.StatusOK, "healthReady")
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/snapshot", "", "1-2"), http.StatusOK, "snapshot")
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/identity", "", ""), http.StatusOK, "nodeIdentity")
	if heartbeat := request(t, client, http.MethodGet, endpoint.URL+"/v1/executor/heartbeat", "", ""); int(heartbeat[0])<<8|int(heartbeat[1]) != http.StatusOK {
		t.Fatalf("heartbeat failed: %s", heartbeat[2:])
	}
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/10000000-0000-4000-8000-000000000000/snapshot", "", ""), http.StatusNotFound, "error")

	var createReceipt harnessprotocol.Receipt
	if err := json.Unmarshal(accepted[2:], &createReceipt); err != nil {
		t.Fatal(err)
	}
	var created harnessprotocol.DialogCreateReferences
	if err := json.Unmarshal(createReceipt.References, &created); err != nil {
		t.Fatal(err)
	}
	enqueue := `{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000202","kind":"message.enqueue","target":{"nodeId":"` + testNodeID + `","dialogId":"` + created.DialogID + `"},"expected":{"dialogVersion":1},"payload":{"text":"safe text"}}`
	enqueued := requestExpected(t, client, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/commands", enqueue, "1-1", &expected)
	validateResponse(t, enqueued, http.StatusAccepted, "receipt")
	var enqueueReceipt harnessprotocol.Receipt
	if err := json.Unmarshal(enqueued[2:], &enqueueReceipt); err != nil {
		t.Fatal(err)
	}
	var message harnessprotocol.MessageEnqueueReferences
	if err := json.Unmarshal(enqueueReceipt.References, &message); err != nil {
		t.Fatal(err)
	}
	activity := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/dialogs?view=activity&limit=10", "", "1-1")
	var activityPage dialogview.Page
	if status := int(activity[0])<<8 | int(activity[1]); status != http.StatusOK || json.Unmarshal(activity[2:], &activityPage) != nil || len(activityPage.Items) != 1 || activityPage.Items[0].State != "queued" {
		t.Fatalf("dialog activity endpoint failed: status=%d body=%s", status, activity[2:])
	}
	readDialog := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/dialogs/"+created.DialogID, "", "1-1")
	var dialogRead dialogview.Read
	if status := int(readDialog[0])<<8 | int(readDialog[1]); status != http.StatusOK || json.Unmarshal(readDialog[2:], &dialogRead) != nil || dialogRead.Dialog.DialogID != created.DialogID {
		t.Fatalf("dialog read endpoint failed: status=%d body=%s", status, readDialog[2:])
	}
	latest := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/dialogs/"+created.DialogID+"/messages?order=latest&limit=10", "", "1-1")
	validateResponse(t, latest, http.StatusOK, "historyPage")
	filtered := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/requests?dialogId="+created.DialogID+"&limit=10", "", "1-1")
	validateResponse(t, filtered, http.StatusOK, "requestPage")
	dispatched, err := authority.DispatchNext(context.Background())
	if err != nil || dispatched.AttemptID == "" {
		t.Fatalf("dispatch failed: %+v err=%v", dispatched, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var current harnessprotocol.Snapshot
		result := authority.Snapshot(context.Background(), node.TrustContext{TransportNodeID: testNodeID})
		if result.HTTPStatus == 200 && json.Unmarshal(result.Body, &current) == nil && current.ActiveAttempt != nil && current.ActiveAttempt.State == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("attempt did not become running")
		}
		time.Sleep(time.Millisecond)
	}
	reference := harnessadapter.AttemptRef{NodeID: testNodeID, DialogID: created.DialogID, RequestID: message.RequestID, AttemptID: dispatched.AttemptID, Generation: 1}
	callID := "40000000-0000-4000-8000-000000000090"
	toolContent := harnessprotocol.SafeContent{Kind: "inline", Content: "safe", Redaction: "none"}
	if err := authority.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolStartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, ToolName: "fixture.echo", ActionHash: strings.Repeat("a", 64), Input: toolContent}); err != nil {
		t.Fatal(err)
	}
	if err := authority.ObserveAdapterEvent(context.Background(), reference, harnessadapter.ToolCompletedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}, CallID: callID, Status: "succeeded", Result: toolContent, EffectStatus: "none"}); err != nil {
		t.Fatal(err)
	}
	tools := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/attempts/"+dispatched.AttemptID+"/tool-calls?limit=10", "", "1-1")
	var toolPage tooltimeline.Page
	if status := int(tools[0])<<8 | int(tools[1]); status != http.StatusOK || json.Unmarshal(tools[2:], &toolPage) != nil || len(toolPage.Items) != 1 || toolPage.Items[0].ToolCallID != callID {
		t.Fatalf("tool timeline endpoint failed: status=%d body=%s", status, tools[2:])
	}
	tool := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/attempts/"+dispatched.AttemptID+"/tool-calls/"+callID+"?limit=10", "", "1-1")
	var toolRead tooltimeline.DetailRead
	if status := int(tool[0])<<8 | int(tool[1]); status != http.StatusOK || json.Unmarshal(tool[2:], &toolRead) != nil || toolRead.ToolCall.ToolCallID != callID || toolRead.ToolCall.Result == nil {
		t.Fatalf("tool detail endpoint failed: status=%d body=%s", status, tool[2:])
	}
	messageID := "40000000-0000-4000-8000-000000000091"
	fullText := strings.Repeat("x", transcriptview.MaximumPreview+17)
	if err := authority.ObserveAdapterEvent(context.Background(), reference, harnessadapter.AssistantMessageEvent{
		EventBase: harnessadapter.EventBase{Attempt: reference}, MessageID: messageID,
		Content:      harnessprotocol.SafeContent{Kind: "inline", Content: fullText[:transcriptview.MaximumPreview], Redaction: "none", Truncated: true},
		FinishReason: "complete", FullText: &fullText,
	}); err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"dialogId": {created.DialogID}, "attemptId": {dispatched.AttemptID}, "sourceKind": {"assistant_message"},
		"sourceId": {messageID}, "sourceIndex": {"0"}, "sourceStream": {"none"},
	}.Encode()
	resolved := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/texts/resolve?"+query, "", "1-1")
	if status := int(resolved[0])<<8 | int(resolved[1]); status != http.StatusOK {
		t.Fatalf("safe text status=%d body=%s", status, resolved[2:])
	}
	manifest, err := transcriptview.Decode(resolved[2:])
	if err != nil || manifest.NodeID != testNodeID || manifest.DialogID != created.DialogID || manifest.AttemptID != dispatched.AttemptID ||
		manifest.Source.ID != messageID || !manifest.Complete || manifest.SizeBytes != int64(len(fullText)) {
		t.Fatalf("safe text endpoint returned wrong source: %+v err=%v", manifest, err)
	}
	chunk := manifest.Chunks[0]
	chunkQuery := url.Values{
		"dialogId": {created.DialogID}, "attemptId": {dispatched.AttemptID}, "sourceKind": {"assistant_message"},
		"sourceId": {messageID}, "sourceIndex": {"0"}, "sourceStream": {"none"}, "artifactId": {chunk.ArtifactID},
		"sizeBytes": {strconv.FormatInt(chunk.SizeBytes, 10)}, "sha256": {chunk.SHA256},
	}.Encode()
	chunkURL := endpoint.URL + "/v1/nodes/" + testNodeID + "/texts/" + manifest.TextID + "/chunks/0?" + chunkQuery
	chunkRequest, err := http.NewRequest(http.MethodGet, chunkURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunkResponse, err := client.Do(chunkRequest)
	if err != nil {
		t.Fatal(err)
	}
	chunkBody, err := io.ReadAll(chunkResponse.Body)
	chunkResponse.Body.Close()
	if err != nil || chunkResponse.StatusCode != http.StatusOK || string(chunkBody) != fullText ||
		chunkResponse.Header.Get(transcriptview.TextIDHeader) != manifest.TextID ||
		chunkResponse.Header.Get(transcriptview.ArtifactIDHeader) != chunk.ArtifactID ||
		chunkResponse.Header.Get(transcriptview.ChunkSHA256Header) != chunk.SHA256 {
		t.Fatalf("exact safe text chunk failed: status=%d headers=%v bytes=%d err=%v", chunkResponse.StatusCode, chunkResponse.Header, len(chunkBody), err)
	}
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/artifacts/"+chunk.ArtifactID+"/metadata", "", "1-1"), http.StatusNotFound, "error")
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/artifacts/"+chunk.ArtifactID, "", "1-1"), http.StatusNotFound, "error")
	wrongChunkQuery := strings.Replace(chunkQuery, chunk.SHA256, strings.Repeat("0", 64), 1)
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/texts/"+manifest.TextID+"/chunks/0?"+wrongChunkQuery, "", "1-1"), http.StatusNotFound, "error")
	invalidQuery := strings.Replace(query, "sourceStream=none", "sourceStream=stdout", 1)
	validateResponse(t, request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/texts/resolve?"+invalidQuery, "", "1-1"), http.StatusBadRequest, "error")
	foreignActorResolved := request(t, client, http.MethodGet, endpoint.URL+"/v1/nodes/"+testNodeID+"/texts/resolve?"+query, "", "1-2")
	if status := int(foreignActorResolved[0])<<8 | int(foreignActorResolved[1]); status != http.StatusOK {
		t.Fatalf("safe text without actor authorization status=%d body=%s", status, foreignActorResolved[2:])
	}
	if _, err := transcriptview.Decode(foreignActorResolved[2:]); err != nil {
		t.Fatalf("safe text without actor authorization is invalid: %v", err)
	}

	deleteDialogCommand := `{"protocolVersion":1,"schemaId":"harness-wire-v2","commandId":"10000000-0000-4000-8000-000000000203","kind":"dialog.create","target":{"nodeId":"` + testNodeID + `"},"expected":{"registryVersion":1},"payload":{}}`
	deleteDialogResponse := requestExpected(t, client, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/commands", deleteDialogCommand, "1-1", &expected)
	validateResponse(t, deleteDialogResponse, http.StatusAccepted, "receipt")
	var deleteDialogReceipt harnessprotocol.Receipt
	var deleteDialog harnessprotocol.DialogCreateReferences
	if json.Unmarshal(deleteDialogResponse[2:], &deleteDialogReceipt) != nil || json.Unmarshal(deleteDialogReceipt.References, &deleteDialog) != nil {
		t.Fatal("logical delete fixture dialog receipt is invalid")
	}
	deleteOperationID := "61000000-0000-4000-8000-000000000003"
	dialogHoldRequest, _ := json.Marshal(harnessbarrier.InstallRequest{
		ProtocolVersion: harnessbarrier.ProtocolVersion, SchemaID: harnessbarrier.SchemaID, OperationID: deleteOperationID,
		NodeID: testNodeID, ExpectedEpoch: expected.IdentityEpoch, BindingGeneration: expected.RegistryVersion,
		Scope: harnessbarrier.Scope{Kind: "dialog", DialogID: deleteDialog.DialogID}, ExpectedScopeRevision: 0,
	})
	dialogHoldResponse := request(t, operatorClient, http.MethodPost, endpoint.URL+"/v1/nodes/"+testNodeID+"/administration/holds", string(dialogHoldRequest), "1-1")
	if status := int(dialogHoldResponse[0])<<8 | int(dialogHoldResponse[1]); status != http.StatusCreated || harnessbarrier.Validate("holdReceipt", dialogHoldResponse[2:]) != nil {
		t.Fatalf("logical delete hold failed: status=%d body=%s", status, dialogHoldResponse[2:])
	}
	var dialogHold harnessbarrier.HoldReceipt
	_ = json.Unmarshal(dialogHoldResponse[2:], &dialogHold)
	deleteRequest, _ := json.Marshal(logicaldelete.NodeRequest{
		SchemaID: logicaldelete.NodeSchemaID, OperationID: deleteOperationID,
		CoordinatorRequestHash: strings.Repeat("a", 64), CommandID: "61000000-0000-4000-8000-000000000004",
		LogicalDialogID: "61000000-0000-4000-8000-000000000001", NodeID: testNodeID, NodeDialogID: deleteDialog.DialogID,
		ExpectedEpoch: dialogHold.Epoch, RegistryVersion: dialogHold.BindingGeneration, BindingVersion: 1,
		ExpectedDialogVersion: 1, HoldVersion: dialogHold.HoldVersion, HoldScopeRevision: dialogHold.ScopeRevision,
	})
	deleteURL := endpoint.URL + "/v1/nodes/" + testNodeID + "/administration/logical-deletes"
	deleted := request(t, client, http.MethodPost, deleteURL, string(deleteRequest), "1-1")
	deleteStatus := int(deleted[0])<<8 | int(deleted[1])
	var nodeReceipt logicaldelete.NodeReceipt
	if deleteStatus != http.StatusCreated || json.Unmarshal(deleted[2:], &nodeReceipt) != nil || logicaldelete.ValidateNodeReceipt(nodeReceipt) != nil {
		t.Fatalf("logical delete endpoint failed: status=%d body=%s", deleteStatus, deleted[2:])
	}
	readDelete := request(t, client, http.MethodGet, deleteURL+"/"+deleteOperationID, "", "1-1")
	if status := int(readDelete[0])<<8 | int(readDelete[1]); status != http.StatusOK || !bytes.Equal(readDelete[2:], deleted[2:]) {
		t.Fatalf("logical delete status endpoint failed: status=%d body=%s", status, readDelete[2:])
	}

	withoutCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "localhost", MinVersion: tls.VersionTLS13}}}
	requestValue, _ := http.NewRequest(http.MethodGet, endpoint.URL+"/health/live", nil)
	response, err := withoutCertificate.Do(requestValue)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unauthenticated private request rejected: status=%v err=%v", response, err)
	}
	response.Body.Close()
}

func request(t *testing.T, client *http.Client, method, url, body, actor string) []byte {
	return requestExpected(t, client, method, url, body, actor, nil)
}

func requestExpected(t *testing.T, client *http.Client, method, url, body, actor string, expected *harnessprotocol.NodeIdentity) []byte {
	t.Helper()
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if expected != nil {
		request.Header.Set(harnessprotocol.ExpectedNodeIDHeader, expected.NodeID)
		request.Header.Set(harnessprotocol.ExpectedRegistryHeader, strconv.FormatInt(expected.RegistryVersion, 10))
		request.Header.Set(harnessprotocol.ExpectedEpochHeader, strconv.FormatInt(expected.IdentityEpoch, 10))
		request.Header.Set(harnessprotocol.ExpectedAdapterKindHeader, expected.Adapter.Kind)
		request.Header.Set(harnessprotocol.ExpectedAdapterVersionHeader, expected.Adapter.Version)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{byte(response.StatusCode >> 8), byte(response.StatusCode)}, content...)
}

func validateResponse(t *testing.T, encoded []byte, status int, wireType string) {
	t.Helper()
	actualStatus := int(encoded[0])<<8 | int(encoded[1])
	body := encoded[2:]
	if actualStatus != status {
		t.Fatalf("status=%d want=%d body=%s", actualStatus, status, body)
	}
	if err := harnessprotocol.Validate(wireType, body); err != nil {
		t.Fatalf("invalid %s: %v body=%s", wireType, err, body)
	}
}

func certificateAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certificate, key, pool
}

func signedCertificate(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, name string, client bool) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.DNSNames = nil
	}
	template.ExtKeyUsage = usage
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}, leaf
}
