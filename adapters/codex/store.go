package codex

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const (
	mappingSchemaVersion = 2
	maximumMappingBytes  = 4 * 1024 * 1024
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type persistedAttempt struct {
	Reference         harnessadapter.AttemptRef      `json:"reference"`
	Context           harnessadapter.ContextBoundary `json:"context"`
	PolicyHash        string                         `json:"policyHash"`
	PromptHash        string                         `json:"promptHash"`
	DispatchKind      string                         `json:"dispatchKind"`
	ThreadID          string                         `json:"threadId,omitempty"`
	TurnID            string                         `json:"turnId,omitempty"`
	ProcessGeneration int64                          `json:"processGeneration,omitempty"`
	State             string                         `json:"state"`
}

type persistedDialog struct {
	ThreadID   string                         `json:"threadId"`
	Boundary   harnessadapter.ContextBoundary `json:"boundary"`
	PolicyHash string                         `json:"policyHash"`
}

type nativeUsage struct {
	InputTokens  int64 `json:"inputTokens"`
	OutputTokens int64 `json:"outputTokens"`
	TotalTokens  int64 `json:"totalTokens"`
}

type mappingState struct {
	SchemaVersion     int                         `json:"schemaVersion"`
	ProcessGeneration int64                       `json:"processGeneration"`
	Attempts          map[string]persistedAttempt `json:"attempts"`
	Dialogs           map[string]persistedDialog  `json:"dialogs"`
}

type mappingStore struct {
	mu       sync.Mutex
	dir      string
	path     string
	contents mappingState
	persist  func(mappingState) error
	poisoned error
}

type indeterminateCommitError struct{ cause error }

func (err *indeterminateCommitError) Error() string {
	return "codex native mapping durability is indeterminate: " + err.cause.Error()
}

func (err *indeterminateCommitError) Unwrap() error { return err.cause }

func openMappingStore(dir string) (*mappingStore, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("codex state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create codex state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("codex state directory is unsafe")
	}
	store := &mappingStore{
		dir: dir, path: filepath.Join(dir, "native-mapping.json"),
		contents: mappingState{
			SchemaVersion: mappingSchemaVersion,
			Attempts:      make(map[string]persistedAttempt),
			Dialogs:       make(map[string]persistedDialog),
		},
	}
	store.persist = store.writeStateLocked
	fileInfo, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o077 != 0 || fileInfo.Size() > maximumMappingBytes {
		return nil, errors.New("codex native mapping file is unsafe")
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		return nil, fmt.Errorf("read codex native mapping: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store.contents); err != nil {
		return nil, errors.New("codex native mapping is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("codex native mapping is invalid")
	}
	if err := validateMappingState(store.contents); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *mappingStore) beginProcess() (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return 0, err
	}
	if store.contents.ProcessGeneration >= harnessprotocol.MaximumSafeInteger {
		return 0, errors.New("codex process generation is exhausted")
	}
	candidate := cloneMappingState(store.contents)
	candidate.ProcessGeneration++
	if err := store.commitCandidateLocked(candidate); err != nil {
		return 0, err
	}
	return candidate.ProcessGeneration, nil
}

func attemptKey(reference harnessadapter.AttemptRef) string {
	return reference.NodeID + "/" + reference.DialogID + "/" + reference.RequestID + "/" + reference.AttemptID + fmt.Sprintf("/%d", reference.Generation)
}

func (store *mappingStore) attempt(reference harnessadapter.AttemptRef) (persistedAttempt, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.contents.Attempts[attemptKey(reference)]
	return value, ok
}

func (store *mappingStore) dialog(dialogID string) (persistedDialog, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.contents.Dialogs[dialogID]
	return value, ok
}

func (store *mappingStore) putIntent(kind string, reference harnessadapter.AttemptRef, boundary harnessadapter.ContextBoundary, policyHash, promptHash, threadID string) error {
	if !validReference(reference) || !validBoundary(boundary) || !validPolicyHash(policyHash) || !validPolicyHash(promptHash) ||
		(kind != "start" && kind != "resume") || (kind == "start" && threadID != "") || (kind == "resume" && !boundedNativeID(threadID)) {
		return errors.New("codex dispatch intent is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return err
	}
	if store.contents.ProcessGeneration < 1 {
		return errors.New("codex app-server process is not initialized")
	}
	key := attemptKey(reference)
	if _, exists := store.contents.Attempts[key]; exists {
		return errors.New("codex dispatch intent already exists")
	}
	candidate := cloneMappingState(store.contents)
	candidate.Attempts[key] = persistedAttempt{
		Reference: reference, Context: boundary, PolicyHash: policyHash, DispatchKind: kind,
		PromptHash: promptHash, ThreadID: threadID, ProcessGeneration: store.contents.ProcessGeneration, State: "thread_dispatching",
	}
	if err := store.commitCandidateLocked(candidate); err != nil {
		return err
	}
	return nil
}

func (store *mappingStore) acknowledgeThread(reference harnessadapter.AttemptRef, threadID string, processGeneration int64) error {
	if !validReference(reference) || !boundedNativeID(threadID) || processGeneration < 1 {
		return errors.New("codex native mapping is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return err
	}
	key := attemptKey(reference)
	intent, exists := store.contents.Attempts[key]
	if !exists || intent.State != "thread_dispatching" || intent.Reference != reference || intent.ProcessGeneration != processGeneration || processGeneration != store.contents.ProcessGeneration ||
		(intent.DispatchKind == "start" && intent.ThreadID != "") || (intent.DispatchKind == "resume" && intent.ThreadID != threadID) {
		return errors.New("codex dispatch intent does not match acknowledgement")
	}
	candidate := cloneMappingState(store.contents)
	intent.ThreadID = threadID
	intent.State = "thread_acknowledged"
	candidate.Attempts[key] = intent
	if err := store.commitCandidateLocked(candidate); err != nil {
		return err
	}
	return nil
}

func (store *mappingStore) beginTurn(reference harnessadapter.AttemptRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return err
	}
	key := attemptKey(reference)
	intent, exists := store.contents.Attempts[key]
	if !exists || intent.State != "thread_acknowledged" || !boundedNativeID(intent.ThreadID) || intent.ProcessGeneration != store.contents.ProcessGeneration {
		return errors.New("codex thread acknowledgement is unavailable")
	}
	candidate := cloneMappingState(store.contents)
	intent.State = "turn_dispatching"
	candidate.Attempts[key] = intent
	return store.commitCandidateLocked(candidate)
}

func (store *mappingStore) activate(reference harnessadapter.AttemptRef, turnID string, processGeneration int64) error {
	if !validReference(reference) || !boundedNativeID(turnID) || processGeneration < 1 {
		return errors.New("codex native mapping is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return err
	}
	key := attemptKey(reference)
	intent, exists := store.contents.Attempts[key]
	if !exists || intent.State != "turn_dispatching" || intent.Reference != reference || !boundedNativeID(intent.ThreadID) ||
		intent.ProcessGeneration != processGeneration || processGeneration != store.contents.ProcessGeneration {
		return errors.New("codex turn intent does not match acknowledgement")
	}
	if dialog, exists := store.contents.Dialogs[reference.DialogID]; exists {
		exactRetryBoundary := intent.Context == dialog.Boundary
		if dialog.ThreadID != intent.ThreadID || intent.Context.Sequence < dialog.Boundary.Sequence ||
			(intent.Context.Sequence == dialog.Boundary.Sequence && !exactRetryBoundary) {
			return errors.New("codex dialog acknowledgement is stale or conflicting")
		}
	}
	candidate := cloneMappingState(store.contents)
	intent.TurnID = turnID
	intent.State = "active"
	candidate.Attempts[key] = intent
	candidate.Dialogs[reference.DialogID] = persistedDialog{ThreadID: intent.ThreadID, Boundary: intent.Context, PolicyHash: intent.PolicyHash}
	return store.commitCandidateLocked(candidate)
}

func (store *mappingStore) terminal(reference harnessadapter.AttemptRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.writableLocked(); err != nil {
		return err
	}
	key := attemptKey(reference)
	value, exists := store.contents.Attempts[key]
	if !exists {
		return nil
	}
	if value.State == "terminal" {
		return nil
	}
	if value.State != "active" {
		return errors.New("codex active attempt is unavailable")
	}
	candidate := cloneMappingState(store.contents)
	value.State = "terminal"
	candidate.Attempts[key] = value
	if err := store.commitCandidateLocked(candidate); err != nil {
		return err
	}
	return nil
}

func (store *mappingStore) writableLocked() error {
	if store.poisoned != nil {
		return errors.New("codex native mapping is unavailable after an indeterminate commit")
	}
	return nil
}

func (store *mappingStore) commitCandidateLocked(candidate mappingState) error {
	err := store.persist(candidate)
	if err == nil {
		store.contents = candidate
		return nil
	}
	var indeterminate *indeterminateCommitError
	if errors.As(err, &indeterminate) {
		// Rename already made candidate visible. Keep memory aligned with the
		// visible file, but prohibit any overwrite until a fresh process reopens
		// and validates the state.
		store.contents = candidate
		store.poisoned = err
	}
	return err
}

func (store *mappingStore) writeStateLocked(state mappingState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > maximumMappingBytes {
		return errors.New("codex native mapping exceeds size limit")
	}
	file, err := os.CreateTemp(store.dir, ".native-mapping-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, store.path); err != nil {
		return err
	}
	keep = true
	directory, err := os.Open(store.dir)
	if err != nil {
		return &indeterminateCommitError{cause: err}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return &indeterminateCommitError{cause: syncErr}
	}
	if closeErr != nil {
		return &indeterminateCommitError{cause: closeErr}
	}
	return nil
}

func cloneMappingState(state mappingState) mappingState {
	clone := state
	clone.Attempts = make(map[string]persistedAttempt, len(state.Attempts))
	for key, value := range state.Attempts {
		clone.Attempts[key] = value
	}
	clone.Dialogs = make(map[string]persistedDialog, len(state.Dialogs))
	for key, value := range state.Dialogs {
		clone.Dialogs[key] = value
	}
	return clone
}

func validateMappingState(state mappingState) error {
	if state.SchemaVersion != mappingSchemaVersion || state.ProcessGeneration < 0 || state.ProcessGeneration > harnessprotocol.MaximumSafeInteger || state.Attempts == nil || state.Dialogs == nil {
		return errors.New("codex native mapping is invalid")
	}
	for key, attempt := range state.Attempts {
		if key != attemptKey(attempt.Reference) || !validReference(attempt.Reference) || !validBoundary(attempt.Context) || !validPolicyHash(attempt.PolicyHash) || !validPolicyHash(attempt.PromptHash) || attempt.ProcessGeneration < 0 || attempt.ProcessGeneration > state.ProcessGeneration {
			return errors.New("codex native mapping is invalid")
		}
		if attempt.DispatchKind != "start" && attempt.DispatchKind != "resume" {
			return errors.New("codex native mapping is invalid")
		}
		switch attempt.State {
		case "thread_dispatching":
			if attempt.TurnID != "" || (attempt.DispatchKind == "start" && attempt.ThreadID != "") || (attempt.DispatchKind == "resume" && !boundedNativeID(attempt.ThreadID)) {
				return errors.New("codex native mapping is invalid")
			}
		case "thread_acknowledged", "turn_dispatching":
			if !boundedNativeID(attempt.ThreadID) || attempt.TurnID != "" {
				return errors.New("codex native mapping is invalid")
			}
		case "active", "terminal":
			if !boundedNativeID(attempt.ThreadID) || !boundedNativeID(attempt.TurnID) {
				return errors.New("codex native mapping is invalid")
			}
		default:
			return errors.New("codex native mapping is invalid")
		}
	}
	for dialogID, dialog := range state.Dialogs {
		if !uuidPattern.MatchString(dialogID) || !boundedNativeID(dialog.ThreadID) || !validBoundary(dialog.Boundary) || !validPolicyHash(dialog.PolicyHash) {
			return errors.New("codex native mapping is invalid")
		}
	}
	return nil
}

func validReference(reference harnessadapter.AttemptRef) bool {
	return uuidPattern.MatchString(reference.NodeID) && uuidPattern.MatchString(reference.DialogID) && uuidPattern.MatchString(reference.RequestID) && uuidPattern.MatchString(reference.AttemptID) && reference.Generation > 0 && reference.Generation <= harnessprotocol.MaximumSafeInteger
}

func validBoundary(boundary harnessadapter.ContextBoundary) bool {
	return uuidPattern.MatchString(boundary.MessageID) && boundary.Sequence > 0 && boundary.Sequence <= harnessprotocol.MaximumSafeInteger
}

func validPolicyHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func boundedNativeID(value string) bool {
	return value != "" && len(value) <= maximumRPCIDBytes && utf8.ValidString(value) && !bytes.ContainsAny([]byte(value), "\x00\r\n")
}

func validNativeUsage(usage nativeUsage) bool {
	return usage.InputTokens >= 0 && usage.OutputTokens >= 0 && usage.TotalTokens >= 0 && usage.InputTokens <= harnessprotocol.MaximumSafeInteger && usage.OutputTokens <= harnessprotocol.MaximumSafeInteger && usage.TotalTokens <= harnessprotocol.MaximumSafeInteger
}
