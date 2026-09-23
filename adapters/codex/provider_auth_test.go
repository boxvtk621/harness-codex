package codex

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/providerauth"
)

const (
	authNodeID   = "10000000-0000-4000-8000-000000000001"
	authCommand1 = "61000000-0000-4000-8000-000000000001"
	authCommand2 = "61000000-0000-4000-8000-000000000002"
	authCommand3 = "61000000-0000-4000-8000-000000000003"
)

func TestProviderAuthPendingIdempotencyCancelAndRestart(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	initial, failure := adapter.Snapshot(ctx, authNodeID)
	if failure != nil || initial.State != "unauthenticated" || initial.Capabilities.Methods[0] != "device_code" {
		t.Fatalf("initial=%+v failure=%+v", initial, failure)
	}
	started, failure := adapter.StartAuth(ctx, authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil || started.Operation.Status != "pending" ||
		started.Operation.VerificationURL == nil || !strings.HasPrefix(*started.Operation.VerificationURL, "https://") ||
		started.Operation.UserCode == nil || started.Operation.TimeoutAt == nil || started.Operation.ExpiresAt != nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	replayed, failure := adapter.StartAuth(ctx, authNodeID, authCommand1, "device_code", nil)
	if failure != nil || replayed.Operation == nil || replayed.Operation.OperationID != started.Operation.OperationID {
		t.Fatalf("replayed=%+v failure=%+v", replayed, failure)
	}
	if _, failure := adapter.StartAuth(ctx, authNodeID, authCommand2, "device_code", nil); failure == nil || failure.Code != "pending_operation" {
		t.Fatalf("concurrent start failure=%+v", failure)
	}
	cancelled, failure := adapter.CancelAuth(ctx, authNodeID, authCommand2, started.Operation.OperationID)
	if failure != nil || cancelled.Operation == nil || cancelled.Operation.Status != "cancelled" || cancelled.Operation.UserCode != nil {
		t.Fatalf("cancelled=%+v failure=%+v", cancelled, failure)
	}
	pending, failure := adapter.StartAuth(ctx, authNodeID, authCommand3, "device_code", nil)
	if failure != nil || pending.Operation == nil || pending.Operation.Status != "pending" {
		t.Fatalf("second pending=%+v failure=%+v", pending, failure)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, failure := reopened.Snapshot(ctx, authNodeID)
	if failure != nil || recovered.Operation == nil || recovered.Operation.Status != "failed" ||
		recovered.Operation.ReasonCode == nil || *recovered.Operation.ReasonCode != "interrupted_by_restart" {
		t.Fatalf("recovered=%+v failure=%+v", recovered, failure)
	}
	historical, failure := reopened.StartAuth(ctx, authNodeID, authCommand1, "device_code", nil)
	if failure != nil || historical.Operation == nil || historical.Operation.OperationID != started.Operation.OperationID || historical.Operation.Status != "cancelled" {
		t.Fatalf("historical replay=%+v failure=%+v", historical, failure)
	}
	lookedUp, failure := reopened.Operation(ctx, authNodeID, started.Operation.OperationID)
	if failure != nil || lookedUp.Operation == nil || lookedUp.Operation.Status != "cancelled" {
		t.Fatalf("historical lookup=%+v failure=%+v", lookedUp, failure)
	}
	info, err := os.Stat(config.StateDir + string(os.PathSeparator) + providerAuthFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("provider auth state mode=%v err=%v", info, err)
	}
}

func TestProviderAuthDoesNotAdoptPreexistingNativeAccount(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_START_AUTHENTICATED=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	snapshot, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || snapshot.State != "unauthenticated" || snapshot.ReasonCode == nil || *snapshot.ReasonCode != "managed_auth_required" {
		t.Fatalf("preexisting native account was adopted: snapshot=%+v failure=%+v", snapshot, failure)
	}
	checked, failure := adapter.Check(context.Background(), authNodeID, authCommand1)
	if failure != nil || checked.State != "unauthenticated" || checked.ReasonCode == nil || *checked.ReasonCode != "managed_auth_required" {
		t.Fatalf("check adopted preexisting native account: checked=%+v failure=%+v", checked, failure)
	}
}

func TestProviderAuthPersistsManagedDeviceCodeProofAcrossRestart(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, failure := adapter.Snapshot(context.Background(), authNodeID)
		if failure != nil {
			t.Fatal(failure.Code)
		}
		if snapshot.State == "authenticated" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	config.Environment = append(config.Environment, "CODEX_AUTH_START_AUTHENTICATED=1")
	reopened, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, failure := reopened.Snapshot(context.Background(), authNodeID)
	if failure != nil || snapshot.State != "authenticated" {
		t.Fatalf("managed proof was not retained: snapshot=%+v failure=%+v", snapshot, failure)
	}
}

func TestProviderAuthCompletionReadbackCheckAndLogout(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	ctx := context.Background()
	started, failure := adapter.StartAuth(ctx, authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	var snapshot = started
	for snapshot.Operation.Status == "pending" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		snapshot, failure = adapter.Snapshot(ctx, authNodeID)
		if failure != nil {
			t.Fatal(failure.Code)
		}
	}
	if snapshot.State != "authenticated" || snapshot.Operation.Status != "succeeded" || snapshot.Operation.UserCode != nil {
		t.Fatalf("completed=%+v", snapshot)
	}
	checked, failure := adapter.Check(ctx, authNodeID, authCommand2)
	if failure != nil || checked.State != "authenticated" || checked.CheckedAt == nil {
		t.Fatalf("checked=%+v failure=%+v", checked, failure)
	}
	loggedOut, failure := adapter.Logout(ctx, authNodeID, authCommand3)
	if failure != nil || loggedOut.State != "unauthenticated" {
		t.Fatalf("loggedOut=%+v failure=%+v", loggedOut, failure)
	}
}

func TestProviderAuthRejectsUnsupportedAndSecretInput(t *testing.T) {
	adapter := newTestAdapter(t, 2*time.Second)
	defer adapter.Close()
	secret := "must-not-be-accepted"
	if _, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "secret", &secret); failure == nil || failure.Code != "unsupported_method" {
		t.Fatalf("unsupported failure=%+v", failure)
	}
	if _, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", &secret); failure == nil || failure.Code != "invalid_request" {
		t.Fatalf("secret failure=%+v", failure)
	}
}

func TestProviderAuthCompletionRequiresUsableRefresh(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_FAIL_REFRESH_AFTER_LOGIN=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, failure := adapter.Snapshot(context.Background(), authNodeID)
		if failure != nil {
			t.Fatal(failure.Code)
		}
		if snapshot.Operation != nil && snapshot.Operation.Status != "pending" {
			if snapshot.State != "unknown" || snapshot.Operation.Status != "failed" || snapshot.Operation.ReasonCode == nil || *snapshot.Operation.ReasonCode != "verification_failed" {
				t.Fatalf("completion accepted without usable refresh: %+v", snapshot)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("completion did not settle")
}

func TestProviderAuthLateCompletionReconcilesAccountWithoutRevivingCancel(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1", "CODEX_AUTH_CANCEL_AUTHENTICATES=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	cancelled, failure := adapter.CancelAuth(context.Background(), authNodeID, authCommand2, started.Operation.OperationID)
	if failure != nil || cancelled.Operation.Status != "cancelled" {
		t.Fatalf("cancelled=%+v failure=%+v", cancelled, failure)
	}
	loginID := adapter.auth.Operation.ProviderLoginID
	adapter.completeProviderLogin(accountLoginCompleted{LoginID: &loginID, Success: true})
	reconciled, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || reconciled.State != "authenticated" || reconciled.Operation.Status != "cancelled" {
		t.Fatalf("late completion=%+v failure=%+v", reconciled, failure)
	}
}

func TestProviderAuthLateCompletionExpiresBeforeReadback(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1", "CODEX_AUTH_CANCEL_AUTHENTICATES=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	loginID := adapter.auth.Operation.ProviderLoginID
	var cancelled cancelLoginResponse
	if err := adapter.session.Call(context.Background(), "account/login/cancel", map[string]string{"loginId": loginID}, &cancelled); err != nil {
		t.Fatal(err)
	}
	past := authTimestamp(time.Now().Add(-time.Second))
	adapter.authMu.Lock()
	adapter.auth.Operation.TimeoutAt = &past
	adapter.authMu.Unlock()

	adapter.completeProviderLogin(accountLoginCompleted{LoginID: &loginID, Success: true, OnboardingEntrypoint: stringPointer("life_sciences")})
	snapshot, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || snapshot.State != "authenticated" || snapshot.Operation == nil || snapshot.Operation.Status != "expired" {
		t.Fatalf("late completion=%+v failure=%+v", snapshot, failure)
	}
}

func TestProviderAuthCompletionReadbackCannotCrossDeadline(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1", "CODEX_AUTH_CANCEL_AUTHENTICATES=1", "CODEX_AUTH_REFRESH_DELAY=100ms")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	loginID := adapter.auth.Operation.ProviderLoginID
	var cancelled cancelLoginResponse
	if err := adapter.session.Call(context.Background(), "account/login/cancel", map[string]string{"loginId": loginID}, &cancelled); err != nil {
		t.Fatal(err)
	}
	deadline := authTimestamp(time.Now().Add(30 * time.Millisecond))
	adapter.authMu.Lock()
	adapter.auth.Operation.TimeoutAt = &deadline
	adapter.authMu.Unlock()
	adapter.completeProviderLogin(accountLoginCompleted{LoginID: &loginID, Success: true, OnboardingEntrypoint: stringPointer("life_sciences")})
	snapshot, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || snapshot.Operation == nil || snapshot.Operation.Status != "expired" ||
		snapshot.Operation.ReasonCode == nil || *snapshot.Operation.ReasonCode != "expired" {
		if snapshot.Operation != nil {
			t.Fatalf("deadline-crossing readback=%+v operation=%+v failure=%+v", snapshot, *snapshot.Operation, failure)
		}
		t.Fatalf("deadline-crossing readback=%+v failure=%+v", snapshot, failure)
	}
}

func TestProviderAuthCheckExpiresMissedCompletionWithoutInferringSuccess(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1", "CODEX_AUTH_CANCEL_AUTHENTICATES=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	loginID := adapter.auth.Operation.ProviderLoginID
	var cancelled cancelLoginResponse
	if err := adapter.session.Call(context.Background(), "account/login/cancel", map[string]string{"loginId": loginID}, &cancelled); err != nil {
		t.Fatal(err)
	}
	past := authTimestamp(time.Now().Add(-time.Second))
	adapter.authMu.Lock()
	adapter.auth.Operation.TimeoutAt = &past
	adapter.authMu.Unlock()

	checked, failure := adapter.Check(context.Background(), authNodeID, authCommand2)
	if failure != nil || checked.State != "unauthenticated" || checked.ReasonCode == nil || *checked.ReasonCode != "managed_auth_required" ||
		checked.Operation == nil || checked.Operation.Status != "expired" {
		t.Fatalf("checked=%+v failure=%+v", checked, failure)
	}
}

func TestProviderAuthV2MigrationRequiresManagedSuccess(t *testing.T) {
	failed := providerAuthState{Version: 2, State: "authenticated", Operation: &storedAuthOperation{Operation: providerauth.Operation{Status: "expired"}}}
	if !migrateProviderAuthState(&failed) || failed.Version != providerAuthVersion || failed.Managed || failed.State != "unauthenticated" ||
		failed.ReasonCode == nil || *failed.ReasonCode != "managed_auth_required" {
		t.Fatalf("expired v2 operation established managed auth: %+v", failed)
	}
	succeeded := providerAuthState{Version: 2, State: "authenticated", Operations: map[string]storedAuthOperation{
		"success": {Operation: providerauth.Operation{Status: "succeeded"}},
	}}
	if !migrateProviderAuthState(&succeeded) || !succeeded.Managed {
		t.Fatalf("successful v2 operation lost managed auth: %+v", succeeded)
	}
}

func TestProviderAuthAcceptsOptionalOnboardingEntrypoint(t *testing.T) {
	for _, shape := range []string{"omitted", "null", "life_sciences"} {
		t.Run(shape, func(t *testing.T) {
			config := testAdapterConfig(t, 2*time.Second)
			config.Environment = append(config.Environment, "CODEX_AUTH_ONBOARDING="+shape)
			adapter, err := New(config, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			snapshot, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
			if failure != nil || snapshot.Operation == nil {
				t.Fatalf("login failed: %+v", failure)
			}
			deadline := time.Now().Add(2 * time.Second)
			for snapshot.Operation.Status == "pending" && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
				snapshot, failure = adapter.Snapshot(context.Background(), authNodeID)
				if failure != nil {
					t.Fatal(failure.Code)
				}
			}
			if snapshot.State != "authenticated" || snapshot.Operation.Status != "succeeded" || snapshot.Operation.UserCode != nil {
				t.Fatalf("completion shape %s: state=%s operation=%s", shape, snapshot.State, snapshot.Operation.Status)
			}
			adapter.authMu.Lock()
			managed := adapter.auth.Managed
			adapter.authMu.Unlock()
			if !managed {
				t.Fatal("successful account readback did not establish managed auth")
			}
		})
	}
}
func TestProviderAuthCompletionShapeRemainsStrict(t *testing.T) {
	loginID := "fixture-login"
	valid := json.RawMessage(`{"loginId":"fixture-login","success":true,"error":null,"onboardingEntrypoint":"life_sciences"}`)
	var completion accountLoginCompleted
	if !decodeStrict(valid, &completion) || completion.LoginID == nil || *completion.LoginID != loginID ||
		completion.OnboardingEntrypoint == nil || *completion.OnboardingEntrypoint != "life_sciences" {
		t.Fatalf("pinned completion was rejected: %+v", completion)
	}
	unknown := json.RawMessage(`{"loginId":"fixture-login","success":true,"error":null,"onboardingEntrypoint":null,"unexpected":true}`)
	if decodeStrict(unknown, &completion) {
		t.Fatal("completion with unknown field was accepted")
	}
}

func TestProviderAuthNotificationRejectsInvalidCompletion(t *testing.T) {
	for name, params := range map[string]json.RawMessage{
		"unknown field": json.RawMessage(`{"loginId":"fixture-login","success":true,"unexpected":true}`),
		"wrong value":   json.RawMessage(`{"loginId":"fixture-login","success":true,"error":null,"onboardingEntrypoint":"future-entrypoint"}`),
	} {
		t.Run(name, func(t *testing.T) {
			future := authTimestamp(time.Now().Add(time.Minute))
			adapter := &Adapter{
				auth: providerAuthState{Operation: &storedAuthOperation{Operation: providerauth.Operation{
					OperationID: "30000000-0000-4000-8000-000000000001", Status: "pending", TimeoutAt: &future,
				}}},
				authCompletions: make(map[string]accountLoginCompleted),
			}
			if !adapter.handleProviderAuthNotification(rpcNotification{Method: "account/login/completed", Params: params}) {
				t.Fatal("provider auth notification was not consumed")
			}
			time.Sleep(10 * time.Millisecond)
			adapter.authMu.Lock()
			defer adapter.authMu.Unlock()
			if len(adapter.authCompletions) != 0 {
				t.Fatalf("non-pinned completion reached auth state: %+v", adapter.authCompletions)
			}
		})
	}
}

func TestAdapterRejectsCredentialPathsInsideWorkspace(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = []string{
		adapterHelperEnvironment, versionHelperEnvironment, "CODEX_VERSION_OUTPUT=codex-cli " + codexAppServerVersion,
		"HOME=" + config.WorkingDir + string(os.PathSeparator) + "home",
		"CODEX_HOME=" + config.WorkingDir + string(os.PathSeparator) + "codex-home",
	}
	if adapter, err := New(config, nil); err == nil {
		adapter.Close()
		t.Fatal("credential paths overlapping the workspace were accepted")
	}
}

func TestAdapterRejectsAbsentCredentialLeafThroughWorkspaceSymlink(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "workspace-alias")
	if err := os.Symlink(workspace, alias); err != nil {
		t.Fatal(err)
	}
	config.WorkingDir = workspace
	config.Environment = []string{
		adapterHelperEnvironment, versionHelperEnvironment, "CODEX_VERSION_OUTPUT=codex-cli " + codexAppServerVersion,
		"HOME=" + filepath.Join(root, "home"), "CODEX_HOME=" + filepath.Join(alias, "missing", "codex-home"),
	}
	if adapter, err := New(config, nil); err == nil {
		adapter.Close()
		t.Fatal("absent credential leaf through workspace symlink was accepted")
	}
}

func TestProviderAuthPreNativePersistenceFailureRollsBack(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	before, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil {
		t.Fatal(failure.Code)
	}
	restore := obstructAuthStateDirectory(t, config.StateDir)
	if _, failure = adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil); failure == nil || failure.Code != "provider_unavailable" {
		t.Fatalf("persistence failure=%+v", failure)
	}
	after, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("state changed before=%+v after=%+v failure=%+v", before, after, failure)
	}
	restore()
}

func TestProviderAuthCompletionPersistenceFailureStaysBlockedAcrossRestart(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1", "CODEX_AUTH_CANCEL_AUTHENTICATES=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	if _, failure = adapter.CancelAuth(context.Background(), authNodeID, authCommand2, started.Operation.OperationID); failure != nil {
		t.Fatal(failure.Code)
	}
	loginID := adapter.auth.Operation.ProviderLoginID
	restore := obstructAuthStateDirectory(t, config.StateDir)
	adapter.completeProviderLogin(accountLoginCompleted{LoginID: &loginID, Success: true})
	blocked, failure := adapter.Snapshot(context.Background(), authNodeID)
	if failure != nil || blocked.State != "unknown" || blocked.Operation == nil || blocked.Operation.Status != "failed" ||
		blocked.Operation.ReasonCode == nil || *blocked.Operation.ReasonCode != "provider_unavailable" {
		t.Fatalf("non-durable completion escaped: %+v failure=%+v", blocked, failure)
	}
	restore()
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, failure := reopened.Snapshot(context.Background(), authNodeID)
	if failure != nil || recovered.State == "authenticated" || recovered.Operation == nil || recovered.Operation.Status == "succeeded" {
		t.Fatalf("restart advertised non-durable completion: %+v failure=%+v", recovered, failure)
	}
}

func obstructAuthStateDirectory(t *testing.T, stateDir string) func() {
	t.Helper()
	backup := stateDir + ".backup"
	if err := os.Rename(stateDir, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateDir, []byte("obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := os.Remove(stateDir); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(backup, stateDir); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)
	return restore
}

func TestProviderAuthMigratesV1ReceiptsAndReplaysSameCommand(t *testing.T) {
	config := testAdapterConfig(t, 2*time.Second)
	config.Environment = append(config.Environment, "CODEX_AUTH_NO_COMPLETE=1")
	adapter, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	started, failure := adapter.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || started.Operation == nil {
		t.Fatalf("started=%+v failure=%+v", started, failure)
	}
	if _, failure = adapter.CancelAuth(context.Background(), authNodeID, authCommand2, started.Operation.OperationID); failure != nil {
		t.Fatal(failure.Code)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	path := config.StateDir + string(os.PathSeparator) + providerAuthFile
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if json.Unmarshal(raw, &legacy) != nil {
		t.Fatal("invalid generated state")
	}
	legacy["version"] = float64(1)
	delete(legacy, "operations")
	for _, value := range legacy["receipts"].(map[string]any) {
		receipt := value.(map[string]any)
		delete(receipt, "createdAt")
		delete(receipt, "failureCode")
		delete(receipt, "failureHttp")
	}
	raw, _ = json.Marshal(legacy)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replayed, failure := reopened.StartAuth(context.Background(), authNodeID, authCommand1, "device_code", nil)
	if failure != nil || replayed.Operation == nil || replayed.Operation.OperationID != started.Operation.OperationID || replayed.Operation.Status != "cancelled" {
		t.Fatalf("v1 replay=%+v failure=%+v", replayed, failure)
	}
	migrated, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(migrated), `"version":3`) || !strings.Contains(string(migrated), `"createdAt"`) {
		t.Fatalf("state was not migrated: %s err=%v", migrated, err)
	}
}
