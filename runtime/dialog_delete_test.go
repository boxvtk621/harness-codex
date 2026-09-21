package node_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/runtime"
)

func TestGenericDialogDeleteRequiresLogicalDeleteCoordinator(t *testing.T) {
	ctx := context.Background()
	opened, err := node.Open(ctx, testConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	dialogID := createDialog(t, ctx, opened, "41000000-0000-4000-8000-000000000001")
	before := currentSnapshot(t, ctx, opened)
	commandID := "41000000-0000-4000-8000-000000000002"
	deleteCommand := command(t, commandID, "dialog.delete",
		map[string]any{"nodeId": testNodeID, "dialogId": dialogID},
		map[string]any{"dialogVersion": 1}, map[string]any{})

	result := opened.SubmitCommand(ctx, nodeTrust(), deleteCommand)
	var wireError harnessprotocol.Error
	if result.HTTPStatus != http.StatusForbidden || json.Unmarshal(result.Body, &wireError) != nil || wireError.Code != "forbidden" {
		t.Fatalf("generic delete status=%d error=%+v body=%s", result.HTTPStatus, wireError, result.Body)
	}
	if status := opened.CommandStatus(ctx, nodeTrust(), commandID); status.HTTPStatus != http.StatusNotFound {
		t.Fatalf("generic delete persisted command: status=%d body=%s", status.HTTPStatus, status.Body)
	}
	if history := opened.History(ctx, nodeTrust(), dialogID, "", 100); history.HTTPStatus != http.StatusOK {
		t.Fatalf("generic delete hid dialog: status=%d body=%s", history.HTTPStatus, history.Body)
	}
	after := currentSnapshot(t, ctx, opened)
	if after.StateVersion != before.StateVersion || after.LastEventSeq != before.LastEventSeq {
		t.Fatalf("generic delete mutated state: before=%+v after=%+v", before, after)
	}
}

func assertDeletedDialogReads(t *testing.T, ctx context.Context, opened *node.Node, dialogID, requestID string) {
	t.Helper()
	var dialogs harnessprotocol.Page[harnessprotocol.DialogSummary]
	result := opened.Dialogs(ctx, nodeTrust(), "", 100)
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &dialogs) != nil || len(dialogs.Items) != 0 {
		t.Fatalf("deleted dialog remains listed: status=%d body=%s", result.HTTPStatus, result.Body)
	}
	if result := opened.History(ctx, nodeTrust(), dialogID, "", 100); result.HTTPStatus != 404 {
		t.Fatalf("deleted history status=%d body=%s", result.HTTPStatus, result.Body)
	}
	var requests harnessprotocol.Page[harnessprotocol.Request]
	result = opened.Requests(ctx, nodeTrust(), "", "", 100)
	if result.HTTPStatus != 200 || json.Unmarshal(result.Body, &requests) != nil || len(requests.Items) != 0 {
		t.Fatalf("deleted requests remain listed: status=%d body=%s", result.HTTPStatus, result.Body)
	}
	if result := opened.Attempts(ctx, nodeTrust(), requestID, "", 100); result.HTTPStatus != 404 {
		t.Fatalf("deleted request attempts status=%d body=%s", result.HTTPStatus, result.Body)
	}
}
