package codex

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

func TestConfirmCompletedApprovalRaceRequiresPriorTerminalProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := openMappingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := store.beginProcess()
	if err != nil {
		t.Fatal(err)
	}
	reference := codexTestReference(1)
	policyHash := strings.Repeat("a", 64)
	if err := store.putIntent("start", reference, codexTestBoundary(1), policyHash, strings.Repeat("b", 64), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.acknowledgeThread(reference, "thread-private-race", generation); err != nil {
		t.Fatal(err)
	}
	if err := store.beginTurn(reference); err != nil {
		t.Fatal(err)
	}
	if err := store.activate(reference, "turn-private-race", generation); err != nil {
		t.Fatal(err)
	}
	if err := store.terminal(reference); err != nil {
		t.Fatal(err)
	}
	adapter := &Adapter{store: store, attempts: make(map[string]*nativeAttempt)}
	if err := adapter.ConfirmCompletedApprovalRace(context.Background(), reference); err == nil {
		t.Fatal("same-process terminal mapping was accepted")
	}
	if _, err := store.beginProcess(); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ConfirmCompletedApprovalRace(context.Background(), reference); err != nil {
		t.Fatalf("prior terminal mapping was rejected: %v", err)
	}
	adapter.attempts[attemptKey(reference)] = &nativeAttempt{reference: reference}
	if err := adapter.ConfirmCompletedApprovalRace(context.Background(), reference); err == nil {
		t.Fatal("active in-memory attempt was accepted")
	}
}

func TestMappingStorePersistsPrivateIDsAndFencesAcknowledgement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := openMappingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := store.beginProcess()
	if err != nil || generation != 1 {
		t.Fatalf("beginProcess = %d, %v", generation, err)
	}
	reference := codexTestReference(1)
	boundary := codexTestBoundary(1)
	policyHash := strings.Repeat("a", 64)
	promptHash := strings.Repeat("d", 64)
	if err := store.putIntent("start", reference, boundary, policyHash, promptHash, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.putIntent("start", reference, boundary, policyHash, promptHash, ""); err == nil {
		t.Fatal("duplicate dispatch intent was accepted")
	}
	if err := store.acknowledgeThread(reference, "thread-private-1", generation); err != nil {
		t.Fatal(err)
	}
	if attempt, _ := store.attempt(reference); attempt.State != "thread_acknowledged" || attempt.ThreadID != "thread-private-1" || attempt.TurnID != "" {
		t.Fatalf("thread acknowledgement = %#v", attempt)
	}
	if err := store.beginTurn(reference); err != nil {
		t.Fatal(err)
	}
	if err := store.activate(reference, "turn-private-1", generation); err != nil {
		t.Fatal(err)
	}

	reopened, err := openMappingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	attempt, exists := reopened.attempt(reference)
	if !exists || attempt.ThreadID != "thread-private-1" || attempt.TurnID != "turn-private-1" || attempt.State != "active" {
		t.Fatalf("attempt = %#v, %v", attempt, exists)
	}
	dialog, exists := reopened.dialog(reference.DialogID)
	if !exists || dialog.ThreadID != "thread-private-1" || dialog.Boundary != boundary || dialog.PolicyHash != policyHash {
		t.Fatalf("dialog = %#v, %v", dialog, exists)
	}
	info, err := os.Lstat(filepath.Join(dir, "native-mapping.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mapping mode = %v, %v", info, err)
	}
	if err := reopened.terminal(reference); err != nil {
		t.Fatal(err)
	}
	terminal, _ := reopened.attempt(reference)
	if terminal.State != "terminal" {
		t.Fatalf("terminal attempt = %#v", terminal)
	}
}

func TestMappingStoreRejectsUnsafeOrCorruptState(t *testing.T) {
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openMappingStore(unsafe); err == nil {
		t.Fatal("unsafe directory was accepted")
	}

	corrupt := filepath.Join(t.TempDir(), "corrupt")
	if err := os.Mkdir(corrupt, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(corrupt, "native-mapping.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"attempts":{},"dialogs":{},"usageByThread":{},"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openMappingStore(corrupt); err == nil {
		t.Fatal("mapping with unknown fields was accepted")
	}
}

func TestMappingStorePersistenceFailureDoesNotPublishCandidateState(t *testing.T) {
	store, err := openMappingStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := store.beginProcess()
	if err != nil {
		t.Fatal(err)
	}
	reference := codexTestReference(1)
	boundary := codexTestBoundary(1)
	policyHash := strings.Repeat("b", 64)
	promptHash := strings.Repeat("d", 64)
	realPersist := store.persist
	failPersist := func(mappingState) error { return errors.New("injected persistence failure") }

	before := cloneMappingState(store.contents)
	store.persist = failPersist
	if _, err := store.beginProcess(); err == nil || !reflect.DeepEqual(store.contents, before) {
		t.Fatalf("failed process commit mutated state: %#v, %v", store.contents, err)
	}
	if err := store.putIntent("start", reference, boundary, policyHash, promptHash, ""); err == nil || !reflect.DeepEqual(store.contents, before) {
		t.Fatalf("failed intent commit mutated state: %#v, %v", store.contents, err)
	}

	store.persist = realPersist
	if err := store.putIntent("start", reference, boundary, policyHash, promptHash, ""); err != nil {
		t.Fatal(err)
	}
	before = cloneMappingState(store.contents)
	store.persist = failPersist
	if err := store.acknowledgeThread(reference, "thread-private-1", generation); err == nil || !reflect.DeepEqual(store.contents, before) {
		t.Fatalf("failed thread acknowledgement mutated state: %#v, %v", store.contents, err)
	}

	store.persist = realPersist
	if err := store.acknowledgeThread(reference, "thread-private-1", generation); err != nil {
		t.Fatal(err)
	}
	if err := store.beginTurn(reference); err != nil {
		t.Fatal(err)
	}
	before = cloneMappingState(store.contents)
	store.persist = failPersist
	if err := store.activate(reference, "turn-private-1", generation); err == nil || !reflect.DeepEqual(store.contents, before) {
		t.Fatalf("failed activation commit mutated state: %#v, %v", store.contents, err)
	}

	store.persist = realPersist
	if err := store.activate(reference, "turn-private-1", generation); err != nil {
		t.Fatal(err)
	}
	before = cloneMappingState(store.contents)
	store.persist = failPersist
	if err := store.terminal(reference); err == nil || !reflect.DeepEqual(store.contents, before) {
		t.Fatalf("failed terminal commit mutated state: %#v, %v", store.contents, err)
	}
}

func TestMappingStorePoisonsWritesAfterIndeterminatePostRenameFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := openMappingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	realPersist := store.persist
	store.persist = func(candidate mappingState) error {
		if err := realPersist(candidate); err != nil {
			return err
		}
		return &indeterminateCommitError{cause: errors.New("injected directory sync failure")}
	}
	if _, err := store.beginProcess(); err == nil {
		t.Fatal("indeterminate commit was reported as successful")
	}
	if store.contents.ProcessGeneration != 1 || store.poisoned == nil {
		t.Fatalf("indeterminate candidate was not retained and poisoned: %#v", store.contents)
	}
	if err := store.putIntent("start", codexTestReference(1), codexTestBoundary(1), strings.Repeat("c", 64), strings.Repeat("d", 64), ""); err == nil || err.Error() != "codex native mapping is unavailable after an indeterminate commit" {
		t.Fatalf("write after indeterminate commit = %v", err)
	}
	reopened, err := openMappingStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.contents.ProcessGeneration != 1 || reopened.poisoned != nil {
		t.Fatalf("reopened mapping = %#v, poisoned=%v", reopened.contents, reopened.poisoned)
	}
}

func codexTestReference(generation int64) harnessadapter.AttemptRef {
	return harnessadapter.AttemptRef{
		NodeID: "10000000-0000-4000-8000-000000000001", DialogID: "20000000-0000-4000-8000-000000000001",
		RequestID: "30000000-0000-4000-8000-000000000001", AttemptID: "40000000-0000-4000-8000-000000000001", Generation: generation,
	}
}

func codexTestBoundary(sequence int64) harnessadapter.ContextBoundary {
	return harnessadapter.ContextBoundary{MessageID: "50000000-0000-4000-8000-000000000001", Sequence: sequence}
}
