package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

// UnsupportedModelRecoveryAdapter has no native process or dispatch capability.
// It may only be passed to runtime.OpenForRecovery.
type UnsupportedModelRecoveryAdapter struct {
	harnessadapter.Adapter
	stateDir, codexHome, model string
}

func (*UnsupportedModelRecoveryAdapter) RecoveryOnlyAdapter() {}

func NewUnsupportedModelRecoveryAdapter(stateDir, codexHome, model string) (*UnsupportedModelRecoveryAdapter, error) {
	if !filepath.IsAbs(stateDir) || !filepath.IsAbs(codexHome) || !rejectionModelPattern.MatchString(model) {
		return nil, errors.New("offline Codex recovery configuration is invalid")
	}
	return &UnsupportedModelRecoveryAdapter{stateDir: stateDir, codexHome: codexHome, model: model}, nil
}

func (*UnsupportedModelRecoveryAdapter) Identity(context.Context) (harnessadapter.Identity, error) {
	declared, verified := make(map[harnessadapter.Capability]bool), make(map[harnessadapter.Capability]bool)
	for _, capability := range []harnessadapter.Capability{
		harnessadapter.CapabilityChat, harnessadapter.CapabilityEvents, harnessadapter.CapabilityToolResults,
		harnessadapter.CapabilityCancel, harnessadapter.CapabilitySteerAttached,
		harnessadapter.CapabilitySessionResume, harnessadapter.CapabilityPolicyEnforcement,
	} {
		declared[capability], verified[capability] = true, true
	}
	return harnessadapter.Identity{Kind: harnessadapter.KindCodex, Version: harnessadapter.CodexAppServerVersion,
		ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
		SchemaSHA256: harnessprotocol.SchemaSHA256, Declared: declared, Verified: verified}, nil
}

// ConfirmUnsupportedModelRejection verifies an immutable, SHA-pinned native
// rollout and a prior terminal mapping. It never opens an app-server.
func (adapter *UnsupportedModelRecoveryAdapter) ConfirmUnsupportedModelRejection(ctx context.Context, ref harnessadapter.AttemptRef, relativePath, expectedSHA string, expectedProcessGeneration int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validReference(ref) || !validPolicyHash(expectedSHA) || expectedProcessGeneration < 2 {
		return errors.New("native recovery proof is invalid")
	}
	store, err := readExistingMapping(adapter.stateDir)
	if err != nil {
		return err
	}
	mapping, exists := store.contents.Attempts[attemptKey(ref)]
	if !exists || mapping.Reference != ref || mapping.State != "terminal" ||
		mapping.ProcessGeneration < 1 || mapping.ProcessGeneration >= expectedProcessGeneration ||
		store.contents.ProcessGeneration != expectedProcessGeneration || !uuidPattern.MatchString(mapping.ThreadID) || !uuidPattern.MatchString(mapping.TurnID) {
		return errors.New("native terminal mapping does not match recovery fence")
	}
	parts := strings.Split(filepath.ToSlash(relativePath), "/")
	if len(parts) != 5 || parts[0] != "sessions" || len(parts[1]) != 4 || len(parts[2]) != 2 || len(parts[3]) != 2 ||
		!strings.HasPrefix(parts[4], "rollout-") || !strings.HasSuffix(parts[4], "-"+mapping.ThreadID+".jsonl") {
		return errors.New("native rollout path does not match thread")
	}
	root, err := os.Lstat(adapter.codexHome)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return errors.New("native rollout root is unsafe")
	}
	path := adapter.codexHome
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\:\x00") {
			return errors.New("native rollout path is invalid")
		}
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("native rollout path is unsafe")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("native rollout is unavailable or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("native rollout exceeds proof bound")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA {
		return errors.New("native rollout hash does not match")
	}
	return verifyUnsupportedModelRollout(raw, mapping.ThreadID, mapping.TurnID, adapter.model)
}

func readExistingMapping(dir string) (*mappingStore, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("native mapping directory is unsafe")
	}
	path := filepath.Join(dir, "native-mapping.json")
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumMappingBytes {
		return nil, errors.New("native mapping file is unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumMappingBytes+1))
	if err != nil || len(raw) > maximumMappingBytes {
		return nil, errors.New("native mapping exceeds bound")
	}
	store := &mappingStore{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&store.contents) != nil || decoder.Decode(new(any)) != io.EOF || validateMappingState(store.contents) != nil {
		return nil, errors.New("native mapping is invalid")
	}
	return store, nil
}

func verifyUnsupportedModelRollout(raw []byte, threadID, turnID, model string) error {
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) < 4 || len(lines) > 64 {
		return errors.New("native rollout record count is invalid")
	}
	started, completed, userItem, modelBound, sessionBound := false, false, false, false, false
	for index, line := range lines {
		if completed {
			return errors.New("native rollout has activity after terminal")
		}
		var record struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if len(line) == 0 || len(line) > 256<<10 || !strictjson.Valid(line) || json.Unmarshal(line, &record) != nil {
			return errors.New("native rollout record is invalid")
		}
		var payload struct {
			Type     string `json:"type"`
			ID       string `json:"id"`
			ThreadID string `json:"thread_id"`
			TurnID   string `json:"turn_id"`
			Role     string `json:"role"`
			Model    string `json:"model"`
			Item     struct {
				Type string `json:"type"`
			} `json:"item"`
			LastAgentMessage string `json:"last_agent_message"`
			Error            *struct {
				Message        string          `json:"message"`
				CodexErrorInfo json.RawMessage `json:"codex_error_info"`
			} `json:"error"`
		}
		if !strictjson.Valid(record.Payload) || json.Unmarshal(record.Payload, &payload) != nil {
			return errors.New("native rollout payload is invalid")
		}
		switch record.Type {
		case "session_meta":
			if index != 0 || sessionBound || payload.ID != threadID {
				return errors.New("native rollout thread does not match")
			}
			sessionBound = true
		case "turn_context":
			if !started || modelBound || payload.TurnID != turnID || payload.Model != model {
				return errors.New("native rollout model or turn does not match")
			}
			modelBound = true
		case "response_item":
			if !started || payload.Type != "message" || (payload.Role != "user" && payload.Role != "developer") {
				return errors.New("native rollout contains assistant or tool activity")
			}
		case "world_state":
			if !started {
				return errors.New("native world state preceded turn")
			}
		case "event_msg":
			switch payload.Type {
			case "task_started":
				if !sessionBound || started || payload.TurnID != turnID {
					return errors.New("native task start does not match")
				}
				started = true
			case "item_completed":
				if !started || completed || payload.TurnID != turnID || payload.ThreadID != threadID || payload.Item.Type != "UserMessage" || userItem {
					return errors.New("native rollout contains non-user item")
				}
				userItem = true
			case "task_complete":
				if !started || completed || payload.TurnID != turnID || payload.LastAgentMessage != "" || payload.Error == nil ||
					unsupportedModelFailure(&nativeTurnError{Message: payload.Error.Message, CodexErrorInfo: payload.Error.CodexErrorInfo}, model) == nil {
					return errors.New("native terminal rejection does not match")
				}
				completed = true
			default:
				return errors.New("native rollout contains other turn activity")
			}
		default:
			return errors.New("native rollout record type is unsupported")
		}
	}
	if !sessionBound || !started || !completed || !userItem || !modelBound {
		return errors.New("native no-effect proof is incomplete")
	}
	return nil
}
