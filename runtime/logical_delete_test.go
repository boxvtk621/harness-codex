package node_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/logicaldelete"
	"github.com/boxvtk621/harness-codex/runtime"
)

func nodeLogicalDeleteRequest(t *testing.T, dialogID, operationID, commandID string, hold harnessbarrier.HoldReceipt, dialogVersion int64) (logicaldelete.NodeRequest, []byte) {
	t.Helper()
	request := logicaldelete.NodeRequest{
		SchemaID: logicaldelete.NodeSchemaID, OperationID: operationID,
		CoordinatorRequestHash: strings.Repeat("a", 64), CommandID: commandID,
		LogicalDialogID: "61000000-0000-4000-8000-000000000001", NodeID: testNodeID, NodeDialogID: dialogID,
		ExpectedEpoch: hold.Epoch, RegistryVersion: hold.BindingGeneration, BindingVersion: 7,
		ExpectedDialogVersion: dialogVersion, HoldVersion: hold.HoldVersion, HoldScopeRevision: hold.ScopeRevision,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return request, raw
}

func TestLogicalDeleteCommitsTombstoneReceiptAndPrivateReplay(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	dialogID := createDialog(t, ctx, opened, "61000000-0000-4000-8000-000000000002")
	operationID := "61000000-0000-4000-8000-000000000003"
	commandID := "61000000-0000-4000-8000-000000000004"
	hold := installHold(t, opened, holdRequest(t, operationID,
		harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, currentSnapshot(t, ctx, opened).Epoch, 0), http.StatusCreated)
	request, raw := nodeLogicalDeleteRequest(t, dialogID, operationID, commandID, hold, 1)
	requestHash, err := logicaldelete.NodeRequestHash(request)
	if err != nil {
		t.Fatal(err)
	}

	deleted := opened.DeleteLogicalDialog(ctx, operatorTrust(), raw)
	if deleted.HTTPStatus != http.StatusCreated || !deleted.Committed {
		t.Fatalf("logical delete status=%d committed=%v body=%s", deleted.HTTPStatus, deleted.Committed, deleted.Body)
	}
	var receipt logicaldelete.NodeReceipt
	if json.Unmarshal(deleted.Body, &receipt) != nil || logicaldelete.ValidateNodeReceipt(receipt) != nil ||
		receipt.NodeRequestHash != requestHash || receipt.DeletedDialogVersion != 2 ||
		receipt.HoldScopeRevision != hold.ScopeRevision+1 {
		t.Fatalf("logical delete receipt invalid: %+v body=%s", receipt, deleted.Body)
	}

	status := opened.LogicalDeleteStatus(ctx, operatorTrust(), operationID)
	if status.HTTPStatus != http.StatusOK || !bytes.Equal(status.Body, deleted.Body) {
		t.Fatalf("private status=%d body=%s want=%s", status.HTTPStatus, status.Body, deleted.Body)
	}
	replay := opened.DeleteLogicalDialog(ctx, operatorTrust(), raw)
	if replay.HTTPStatus != http.StatusOK || !bytes.Equal(replay.Body, deleted.Body) {
		t.Fatalf("private replay=%d body=%s want=%s", replay.HTTPStatus, replay.Body, deleted.Body)
	}
	if generic := opened.CommandStatus(ctx, nodeTrust(), commandID); generic.HTTPStatus != http.StatusNotFound {
		t.Fatalf("generic command status exposed tombstone receipt: status=%d body=%s", generic.HTTPStatus, generic.Body)
	}
	assertDeletedDialogReads(t, ctx, opened, dialogID, "61000000-0000-4000-8000-000000000099")
}

func TestLogicalDeleteLostACKReconcilesOnlyThroughPrivateReceipt(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "62000000-0000-4000-8000-000000000001")
	operationID := "62000000-0000-4000-8000-000000000002"
	commandID := "62000000-0000-4000-8000-000000000003"
	hold := installHold(t, opened, holdRequest(t, operationID,
		harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, currentSnapshot(t, ctx, opened).Epoch, 0), http.StatusCreated)
	_, raw := nodeLogicalDeleteRequest(t, dialogID, operationID, commandID, hold, 1)

	opened.SetFaultInjector(func(point node.FaultPoint) error {
		if point == node.FaultAfterLogicalDeleteCommit {
			return errors.New("synthetic lost logical delete receipt")
		}
		return nil
	})
	lost := opened.DeleteLogicalDialog(ctx, operatorTrust(), raw)
	if lost.HTTPStatus != http.StatusServiceUnavailable || !lost.Committed {
		t.Fatalf("lost ACK status=%d committed=%v body=%s", lost.HTTPStatus, lost.Committed, lost.Body)
	}
	opened.SetFaultInjector(nil)
	status := opened.LogicalDeleteStatus(ctx, operatorTrust(), operationID)
	if status.HTTPStatus != http.StatusOK {
		t.Fatalf("private reconciliation status=%d body=%s", status.HTTPStatus, status.Body)
	}
	if generic := opened.CommandStatus(ctx, nodeTrust(), commandID); generic.HTTPStatus != http.StatusNotFound {
		t.Fatalf("generic reconciliation exposed receipt: status=%d body=%s", generic.HTTPStatus, generic.Body)
	}
	if replay := opened.DeleteLogicalDialog(ctx, operatorTrust(), raw); replay.HTTPStatus != http.StatusOK || !bytes.Equal(replay.Body, status.Body) {
		t.Fatalf("private replay status=%d body=%s want=%s", replay.HTTPStatus, replay.Body, status.Body)
	}
}

func TestLogicalDeleteBusyGuardKeepsHoldAndDialog(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "63000000-0000-4000-8000-000000000001")
	enqueue(t, ctx, opened, "63000000-0000-4000-8000-000000000002", dialogID, "busy", 1)
	operationID := "63000000-0000-4000-8000-000000000003"
	hold := installHold(t, opened, holdRequest(t, operationID,
		harnessbarrier.Scope{Kind: "dialog", DialogID: dialogID}, currentSnapshot(t, ctx, opened).Epoch, 0), http.StatusCreated)
	_, raw := nodeLogicalDeleteRequest(t, dialogID, operationID, "63000000-0000-4000-8000-000000000004", hold, 2)

	rejected := opened.DeleteLogicalDialog(ctx, operatorTrust(), raw)
	if rejected.HTTPStatus != http.StatusConflict || rejected.Committed {
		t.Fatalf("busy delete status=%d committed=%v body=%s", rejected.HTTPStatus, rejected.Committed, rejected.Body)
	}
	if status := opened.HoldStatus(ctx, operatorTrust(), operationID); status.HTTPStatus != http.StatusOK {
		t.Fatalf("busy rejection released hold: status=%d body=%s", status.HTTPStatus, status.Body)
	}
	if history := opened.History(ctx, nodeTrust(), dialogID, "", 100); history.HTTPStatus != http.StatusOK {
		t.Fatalf("busy rejection tombstoned dialog: status=%d body=%s", history.HTTPStatus, history.Body)
	}
	if release := opened.ReleaseHold(ctx, operatorTrust(), releaseRequest(t, hold, "cancel")); release.HTTPStatus != http.StatusCreated {
		t.Fatalf("hold cancel status=%d body=%s", release.HTTPStatus, release.Body)
	}
}
