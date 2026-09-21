package node

import (
	"context"
	"fmt"
	"testing"
)

func TestDeletedMessageScopesBoundsEachReplayWindow(t *testing.T) {
	opened := openDeleteNode(t)
	defer opened.Close()
	dialogID := createDeleteTestDialog(t, opened)
	seedDeleteAttempt(t, opened, dialogID, "completed", "completed")
	if result := submitDelete(t, opened, dialogID, 1); result.HTTPStatus != 201 {
		t.Fatalf("delete status=%d body=%s", result.HTTPStatus, result.Body)
	}

	candidates := map[string]struct{}{
		"42000000-0000-4000-8000-000000000010": {},
	}
	for index := 0; index < 99; index++ {
		candidates[fmt.Sprintf("43000000-0000-4000-8000-%012d", index)] = struct{}{}
	}
	tx, err := opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	deleted, err := deletedMessageScopes(context.Background(), tx, candidates, opened.deletedDialogs)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("deleted message candidates=%v", deleted)
	}
	if _, ok := deleted["42000000-0000-4000-8000-000000000010"]; !ok {
		t.Fatal("deleted replay-window message was not detected")
	}
	candidates["43000000-0000-4000-8000-000000000100"] = struct{}{}
	if _, err := deletedMessageScopes(context.Background(), tx, candidates, opened.deletedDialogs); err == nil {
		t.Fatal("unbounded replay message candidate set was accepted")
	}
}
