package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/diagnosticlog"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/providerauth"
	node "github.com/boxvtk621/harness-codex/runtime"
)

func TestDiagnosticAuthAndReadinessLogTransitionsWithoutSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := diagnosticlog.New(diagnosticlog.Config{Writer: &output, Component: "api"})
	logger.SetNodeID("10000000-0000-4000-8000-000000000001")
	server := &Server{config: Config{NodeID: "10000000-0000-4000-8000-000000000001", Logger: logger}}
	secretURL, userCode := "https://provider.invalid/?secret=canary", "SECRET-CANARY"
	envelope := providerauth.Envelope{NodeID: server.config.NodeID, State: "unauthenticated", Operation: &providerauth.Operation{
		OperationID: "20000000-0000-4000-8000-000000000002", CommandID: "30000000-0000-4000-8000-000000000003",
		Method: "device_code", Status: "pending", VerificationURL: &secretURL, UserCode: &userCode,
	}}
	body, _ := json.Marshal(envelope)
	result := node.Result{HTTPStatus: 200, Body: body}
	server.logAuthResult(result, "operation", "", envelope.Operation.OperationID)
	snapshot := envelope
	snapshot.Operation = nil
	snapshotBody, _ := json.Marshal(snapshot)
	server.logAuthResult(node.Result{HTTPStatus: 200, Body: snapshotBody}, "snapshot", "", "")
	server.logAuthResult(result, "operation", "", envelope.Operation.OperationID)
	for index := 0; index < 65; index++ {
		other := envelope
		operation := *envelope.Operation
		operation.OperationID = fmt.Sprintf("operation-%d", index)
		other.Operation = &operation
		otherBody, _ := json.Marshal(other)
		server.logAuthResult(node.Result{HTTPStatus: 200, Body: otherBody}, "operation", "", operation.OperationID)
	}
	server.logAuthResult(result, "operation", "", envelope.Operation.OperationID)
	envelope.Operation.Status = "succeeded"
	body, _ = json.Marshal(envelope)
	server.logAuthResult(node.Result{HTTPStatus: 200, Body: body}, "operation", "", envelope.Operation.OperationID)
	health, _ := json.Marshal(harnessprotocol.HealthReady{Readiness: "blocked", BlockedReasons: []string{"auth_unavailable"}})
	server.logReadiness(node.Result{HTTPStatus: 503, Body: health})
	server.logReadiness(node.Result{HTTPStatus: 503, Body: health})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := logger.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	logged := output.String()
	if strings.Count(logged, `"event":"provider.auth_started"`) != 66 || strings.Count(logged, `"event":"readiness.changed"`) != 1 ||
		!strings.Contains(logged, `"event":"provider.auth_completed"`) {
		t.Fatalf("unexpected transitions: %s", logged)
	}
	if strings.Contains(logged, "SECRET-CANARY") || strings.Contains(logged, "provider.invalid") {
		t.Fatalf("secret escaped: %s", logged)
	}
}
