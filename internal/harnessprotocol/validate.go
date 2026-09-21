package harnessprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/boxvtk621/harness-codex/internal/strictjson"
)

type check func(any) error
type property struct {
	check    check
	optional bool
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var actorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
var integerPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
var timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

func required(c check) property { return property{check: c} }
func optional(c check) property { return property{check: c, optional: true} }

func object(fields map[string]property) check {
	return func(value any) error {
		item, ok := value.(map[string]any)
		if !ok {
			return errors.New("must be object")
		}
		for key := range item {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("unknown field %q", key)
			}
		}
		for key, field := range fields {
			value, ok := item[key]
			if !ok {
				if field.optional {
					continue
				}
				return fmt.Errorf("missing field %q", key)
			}
			if err := field.check(value); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
		return nil
	}
}

func list(itemCheck check, maximum int) check {
	return func(value any) error {
		items, ok := value.([]any)
		if !ok || len(items) > maximum {
			return errors.New("invalid array")
		}
		for index, item := range items {
			if err := itemCheck(item); err != nil {
				return fmt.Errorf("item %d: %w", index, err)
			}
		}
		return nil
	}
}

func union(checks ...check) check {
	return func(value any) error {
		matched := 0
		for _, candidate := range checks {
			if candidate(value) == nil {
				matched++
			}
		}
		if matched != 1 {
			return errors.New("must match exactly one variant")
		}
		return nil
	}
}

func stringCheck(minimum, maximum int) check {
	return func(value any) error {
		item, ok := value.(string)
		if !ok || len([]byte(item)) < minimum || len([]byte(item)) > maximum {
			return errors.New("invalid UTF-8 byte length")
		}
		return nil
	}
}

func unicodeStringCheck(minimumCodePoints, maximumCodePoints, maximumBytes int) check {
	return func(value any) error {
		item, ok := value.(string)
		if !ok {
			return errors.New("must be string")
		}
		codePoints := len([]rune(item))
		if codePoints < minimumCodePoints || codePoints > maximumCodePoints || len([]byte(item)) > maximumBytes {
			return errors.New("invalid Unicode or UTF-8 byte length")
		}
		return nil
	}
}

func enumCheck(values ...string) check {
	allowed := make(map[string]bool, len(values))
	for _, value := range values {
		allowed[value] = true
	}
	return func(value any) error {
		item, ok := value.(string)
		if !ok || !allowed[item] {
			return errors.New("unknown enum value")
		}
		return nil
	}
}

func integerCheck(positive bool, maximum int64) check {
	return func(value any) error {
		item, ok := jsonInteger(value)
		if !ok || item < 0 || item > maximum || (positive && item == 0) {
			return errors.New("invalid safe integer")
		}
		return nil
	}
}

var safeInteger = integerCheck(false, MaximumSafeInteger)
var positiveInteger = integerCheck(true, MaximumSafeInteger)
var booleanCheck check = func(value any) error {
	if _, ok := value.(bool); !ok {
		return errors.New("must be boolean")
	}
	return nil
}
var uuidCheck check = func(value any) error {
	item, ok := value.(string)
	if !ok || !uuidPattern.MatchString(item) {
		return errors.New("invalid canonical UUID")
	}
	return nil
}
var sha256Check check = func(value any) error {
	item, ok := value.(string)
	if !ok || !sha256Pattern.MatchString(item) {
		return errors.New("invalid SHA-256")
	}
	return nil
}
var schemaSHA256Check check = func(value any) error {
	item, ok := value.(string)
	if !ok || item != SchemaSHA256 {
		return errors.New("schema SHA-256 mismatch")
	}
	return nil
}
var actorCheck check = func(value any) error {
	item, ok := value.(string)
	if !ok || !actorPattern.MatchString(item) {
		return errors.New("invalid actor identity")
	}
	return nil
}
var timestampCheck check = func(value any) error {
	item, ok := value.(string)
	if !ok {
		return errors.New("must be timestamp")
	}
	if !timestampPattern.MatchString(item) {
		return errors.New("invalid canonical timestamp grammar")
	}
	if _, err := time.Parse(time.RFC3339Nano, item); err != nil {
		return errors.New("invalid RFC3339 timestamp")
	}
	return nil
}
var nullCheck check = func(value any) error {
	if value != nil {
		return errors.New("must be null")
	}
	return nil
}

func nullable(c check) check { return union(c, nullCheck) }

var targetNode = object(map[string]property{"nodeId": required(uuidCheck)})
var targetDialog = object(map[string]property{"nodeId": required(uuidCheck), "dialogId": required(uuidCheck)})
var targetSteer = object(map[string]property{"nodeId": required(uuidCheck), "dialogId": required(uuidCheck), "attemptId": required(uuidCheck), "messageId": required(uuidCheck)})
var targetRequest = object(map[string]property{"nodeId": required(uuidCheck), "requestId": required(uuidCheck)})
var targetAttempt = object(map[string]property{"nodeId": required(uuidCheck), "attemptId": required(uuidCheck)})
var targetApproval = object(map[string]property{"nodeId": required(uuidCheck), "approvalId": required(uuidCheck), "attemptId": required(uuidCheck)})
var targetInput = object(map[string]property{"nodeId": required(uuidCheck), "inputRequestId": required(uuidCheck), "attemptId": required(uuidCheck)})
var emptyObject = object(map[string]property{})

type commandRule struct{ target, expected, payload check }

var commandRules = map[CommandKind]commandRule{
	CommandDialogCreate:    {targetNode, object(map[string]property{"registryVersion": required(safeInteger)}), object(map[string]property{"title": optional(stringCheck(1, 200))})},
	CommandDialogDelete:    {targetDialog, object(map[string]property{"dialogVersion": required(safeInteger)}), emptyObject},
	CommandMessageEnqueue:  {targetDialog, object(map[string]property{"dialogVersion": required(safeInteger)}), object(map[string]property{"text": required(stringCheck(1, MaximumMessageBytes))})},
	CommandMessageSteer:    {targetSteer, object(map[string]property{"attemptGeneration": required(safeInteger), "messageVersion": required(safeInteger)}), emptyObject},
	CommandRequestCancel:   {targetRequest, object(map[string]property{"requestVersion": required(safeInteger)}), emptyObject},
	CommandAttemptStop:     {targetAttempt, object(map[string]property{"attemptGeneration": required(safeInteger)}), emptyObject},
	CommandQueueResume:     {targetNode, object(map[string]property{"queueVersion": required(safeInteger)}), emptyObject},
	CommandAttemptRetry:    {targetAttempt, object(map[string]property{"attemptGeneration": required(safeInteger)}), object(map[string]property{"acknowledgeKnownEffects": required(booleanCheck)})},
	CommandApprovalRespond: {targetApproval, object(map[string]property{"approvalVersion": required(safeInteger), "attemptGeneration": required(safeInteger)}), object(map[string]property{"decision": required(enumCheck("allow_once", "deny")), "actionHash": required(sha256Check)})},
	CommandInputRespond:    {targetInput, object(map[string]property{"inputVersion": required(safeInteger), "attemptGeneration": required(safeInteger)}), object(map[string]property{"text": required(stringCheck(1, MaximumMessageBytes))})},
}

var receiptReferences = map[CommandKind]check{
	CommandDialogCreate:   object(map[string]property{"dialogId": required(uuidCheck)}),
	CommandDialogDelete:   object(map[string]property{"dialogId": required(uuidCheck)}),
	CommandMessageEnqueue: object(map[string]property{"dialogId": required(uuidCheck), "messageId": required(uuidCheck), "requestId": required(uuidCheck)}),
	CommandMessageSteer:   object(map[string]property{"dialogId": required(uuidCheck), "messageId": required(uuidCheck), "attemptId": required(uuidCheck)}),
	CommandRequestCancel:  object(map[string]property{"requestId": required(uuidCheck)}), CommandAttemptStop: object(map[string]property{"attemptId": required(uuidCheck)}),
	CommandQueueResume:     object(map[string]property{"nodeId": required(uuidCheck)}),
	CommandAttemptRetry:    object(map[string]property{"priorAttemptId": required(uuidCheck), "requestId": required(uuidCheck)}),
	CommandApprovalRespond: object(map[string]property{"approvalId": required(uuidCheck), "attemptId": required(uuidCheck)}),
	CommandInputRespond:    object(map[string]property{"inputRequestId": required(uuidCheck), "attemptId": required(uuidCheck), "messageId": required(uuidCheck)}),
}

var nodeStateCheck = object(map[string]property{
	"transportAvailability": required(enumCheck("online", "stale", "offline")), "engineReadiness": required(enumCheck("ready", "blocked", "unknown")),
	"occupancy": required(enumCheck("idle", "active", "unknown")), "queuePaused": required(booleanCheck), "queueVersion": required(safeInteger),
	"pendingCount": required(safeInteger), "blockedReasons": required(list(enumCheck("engine_unavailable", "auth_unavailable", "quota_exhausted", "policy_unavailable", "capability_missing", "storage_unavailable", "execution_unknown", "adapter_protocol", "operator_pause"), 16)),
	"activeAttemptId": required(nullable(uuidCheck)),
})
var dialogCheck = object(map[string]property{"dialogId": required(uuidCheck), "version": required(safeInteger), "title": optional(stringCheck(1, 200)), "createdAt": required(timestampCheck)})
var userHistoryCheck check
var assistantHistoryCheck check
var historyCheck check
var requestCheck = object(map[string]property{"requestId": required(uuidCheck), "dialogId": required(uuidCheck), "inputMessageId": required(uuidCheck), "queueSequence": required(positiveInteger), "version": required(safeInteger), "status": required(enumCheck("queued", "cancelled", "dispatching", "active", "completed", "failed", "interrupted", "unknown"))})
var usageCheck = object(map[string]property{"source": required(enumCheck("per_attempt", "cumulative_process")), "inputTokens": required(safeInteger), "outputTokens": required(safeInteger), "totalTokens": required(safeInteger)})
var attemptCheck = object(map[string]property{"attemptId": required(uuidCheck), "dialogId": required(uuidCheck), "requestId": required(uuidCheck), "generation": required(positiveInteger), "version": required(safeInteger), "state": required(enumCheck("dispatching", "running", "waiting_input", "stopping", "completed", "failed", "interrupted", "unknown")), "effectStatus": required(enumCheck("none", "known", "unknown")), "startedAt": optional(timestampCheck), "finishedAt": optional(timestampCheck)})

var inlineSafeContent = object(map[string]property{"kind": required(enumCheck("inline")), "content": required(stringCheck(0, MaximumMessageBytes)), "redaction": required(enumCheck("none", "applied")), "truncated": required(booleanCheck)})
var artifactSafeContent = object(map[string]property{"kind": required(enumCheck("artifact")), "artifactId": required(uuidCheck), "sizeBytes": required(integerCheck(false, MaximumArtifactBytes)), "sha256": required(sha256Check), "redaction": required(enumCheck("none", "applied")), "truncated": required(booleanCheck)})
var unavailableSafeContent = object(map[string]property{"kind": required(enumCheck("unavailable")), "reason": required(enumCheck("not_observed", "provider_redacted", "output_limit", "unmapped")), "redaction": required(enumCheck("none", "applied", "unknown")), "truncated": required(booleanCheck)})
var safeContentCheck = union(inlineSafeContent, artifactSafeContent, unavailableSafeContent)
var attemptOutputCheck = union(object(map[string]property{"kind": required(enumCheck("message")), "assistantMessageId": required(uuidCheck)}), object(map[string]property{"kind": required(enumCheck("empty"))}))

func init() {
	userHistoryCheck = object(map[string]property{"messageId": required(uuidCheck), "role": required(enumCheck("user")), "dialogId": required(uuidCheck), "sequence": required(positiveInteger), "version": required(safeInteger), "createdAt": required(timestampCheck), "text": required(stringCheck(1, MaximumMessageBytes)), "disposition": required(enumCheck("queued", "steer_pending", "applied", "cancelled", "unknown")), "commandId": required(uuidCheck), "requestId": required(uuidCheck)})
	assistantHistoryCheck = object(map[string]property{"messageId": required(uuidCheck), "role": required(enumCheck("assistant")), "dialogId": required(uuidCheck), "sequence": required(positiveInteger), "version": required(safeInteger), "createdAt": required(timestampCheck), "attemptId": required(uuidCheck), "content": required(safeContentCheck), "finishReason": required(enumCheck("complete", "length", "cancelled", "error"))})
	historyCheck = union(userHistoryCheck, assistantHistoryCheck)
}

var eventPayloadChecks = map[string]check{
	"node.state_changed":          nodeStateCheck,
	"dialog.deleted":              object(map[string]property{"dialogId": required(uuidCheck)}),
	"queue.changed":               object(map[string]property{"queueVersion": required(safeInteger), "pendingCount": required(safeInteger), "activeAttemptId": required(nullable(uuidCheck)), "queuePaused": required(booleanCheck)}),
	"message.accepted":            object(map[string]property{"dialogId": required(uuidCheck), "messageId": required(uuidCheck), "requestId": required(uuidCheck), "sequence": required(positiveInteger), "disposition": required(enumCheck("queued"))}),
	"message.disposition_changed": object(map[string]property{"messageId": required(uuidCheck), "from": required(enumCheck("queued", "steer_pending", "applied", "cancelled", "unknown")), "to": required(enumCheck("queued", "steer_pending", "applied", "cancelled", "unknown")), "reasonCode": required(enumCheck("request_dispatched", "steer_requested", "steer_applied", "steer_fallback", "steer_unknown", "request_cancelled", "reconciled"))}),
	"attempt.dispatching":         object(map[string]property{"requestId": required(uuidCheck), "generation": required(positiveInteger), "contextBoundaryMessageId": required(uuidCheck), "policyRevision": required(stringCheck(1, 200)), "policyHash": required(sha256Check)}),
	"attempt.started":             object(map[string]property{"requestId": required(uuidCheck), "generation": required(positiveInteger)}),
	"attempt.waiting_input":       object(map[string]property{"requestId": required(uuidCheck), "generation": required(positiveInteger), "waitKind": required(enumCheck("approval", "input"))}),
	"attempt.stop_requested":      object(map[string]property{"generation": required(positiveInteger), "commandId": required(uuidCheck)}),
	"attempt.completed":           object(map[string]property{"generation": required(positiveInteger), "output": required(attemptOutputCheck), "usage": optional(usageCheck)}),
	"attempt.failed":              object(map[string]property{"generation": required(positiveInteger), "failureClass": required(enumCheck("task", "node", "policy", "protocol")), "errorCode": required(stringCheck(1, 200)), "safeMessage": required(stringCheck(1, 500)), "retryable": required(booleanCheck), "effectStatus": required(enumCheck("none", "known", "unknown"))}),
	"attempt.interrupted":         object(map[string]property{"generation": required(positiveInteger), "reason": required(enumCheck("owner_stop", "provider_interrupt", "process_exit")), "effectStatus": required(enumCheck("none", "known", "unknown"))}),
	"attempt.unknown":             object(map[string]property{"generation": required(positiveInteger), "reason": required(enumCheck("dispatch_uncertain", "cancel_unconfirmed", "adapter_protocol", "provider_state", "unmapped_event")), "effectStatus": required(enumCheck("none", "known", "unknown"))}),
	"assistant.delta":             object(map[string]property{"messageId": required(uuidCheck), "deltaIndex": required(safeInteger), "content": required(safeContentCheck)}),
	"assistant.message":           object(map[string]property{"messageId": required(uuidCheck), "content": required(safeContentCheck), "finishReason": required(enumCheck("complete", "length", "cancelled", "error"))}),
	"tool.started":                object(map[string]property{"callId": required(uuidCheck), "toolName": required(stringCheck(1, 200)), "actionHash": required(sha256Check), "input": required(safeContentCheck)}),
	"tool.output":                 object(map[string]property{"callId": required(uuidCheck), "chunkIndex": required(safeInteger), "stream": required(enumCheck("stdout", "stderr", "result", "diagnostic")), "output": required(safeContentCheck)}),
	"tool.completed":              object(map[string]property{"callId": required(uuidCheck), "status": required(enumCheck("succeeded", "failed", "unknown")), "result": required(safeContentCheck), "effectStatus": required(enumCheck("none", "known", "unknown")), "effectRef": optional(stringCheck(1, 200))}),
	"approval.requested":          object(map[string]property{"approvalId": required(uuidCheck), "callId": required(uuidCheck), "actionHash": required(sha256Check), "safePrompt": required(unicodeStringCheck(1, 2000, 8192)), "approvalVersion": required(safeInteger)}),
	"approval.resolved":           object(map[string]property{"approvalId": required(uuidCheck), "decision": required(enumCheck("allow_once", "deny")), "actorId": required(actorCheck), "approvalVersion": required(safeInteger)}),
	"input.requested":             object(map[string]property{"inputRequestId": required(uuidCheck), "prompt": required(safeContentCheck), "inputVersion": required(safeInteger)}),
	"input.resolved":              object(map[string]property{"inputRequestId": required(uuidCheck), "messageId": required(uuidCheck), "inputVersion": required(safeInteger)}),
	"artifact.available":          object(map[string]property{"artifactId": required(uuidCheck), "callId": optional(uuidCheck), "name": required(stringCheck(1, 200)), "mediaType": required(stringCheck(1, 200)), "sizeBytes": required(integerCheck(false, MaximumArtifactBytes)), "sha256": required(sha256Check), "redaction": required(enumCheck("none", "applied")), "truncated": required(booleanCheck)}),
	"history.gap":                 object(map[string]property{"expectedSeq": required(positiveInteger), "availableFromSeq": required(positiveInteger), "reason": required(enumCheck("storage_corruption", "identity_changed", "unmapped_event"))}),
}

func Validate(wireType string, data []byte) error {
	value, err := decodeObject(data)
	if err != nil {
		return err
	}
	switch wireType {
	case "command":
		return validateCommand(value)
	case "receipt":
		return validateReceipt(value)
	case "error":
		return validateError(value)
	case "event":
		return validateEvent(value)
	case "snapshot":
		return validateSnapshot(value)
	case "dialogPage":
		return validatePage(value, "dialogs", dialogCheck)
	case "historyPage":
		return validateHistoryPage(value)
	case "requestPage":
		return validatePage(value, "requests", requestCheck)
	case "attemptPage":
		return validateAttemptPage(value)
	case "eventPage":
		return validateEventPage(value)
	case "attemptRead":
		return validateAttemptRead(value)
	case "commandStatus":
		return validateCommandStatus(value)
	case "nodeIdentity":
		return validateNodeIdentity(value)
	case "admissionProfile":
		return validateAdmissionProfile(value)
	case "healthLive":
		return validateHealthLive(value)
	case "healthReady":
		return validateHealthReady(value)
	case "artifactMetadata":
		return validateArtifactMetadata(value)
	default:
		return fmt.Errorf("unknown wire type %q", wireType)
	}
}

func validateAdmissionProfile(value map[string]any) error {
	capabilities := object(map[string]property{
		"profile": required(booleanCheck), "native_epoch": required(booleanCheck),
		"policy_enforcement": required(booleanCheck), "history": required(booleanCheck),
		"facts": required(booleanCheck), "durable_receipts": required(booleanCheck),
		"replica_export": required(booleanCheck), "replica_import": required(booleanCheck),
		"asset_export": required(booleanCheck), "asset_import": required(booleanCheck),
		"scoped_quiesce": required(booleanCheck), "ownership_release": required(booleanCheck),
		"target_reservation": required(booleanCheck),
	})
	return object(map[string]property{
		"schemaId": required(enumCheck(AdmissionSchemaID)), "ownerId": required(actorCheck),
		"nodeId": required(uuidCheck), "registrationRevision": required(positiveInteger),
		"identityEpoch": required(positiveInteger), "wireSchemaSHA256": required(schemaSHA256Check),
		"adapter": required(adapterIdentityCheck), "readiness": required(enumCheck("ready", "blocked", "unknown")),
		"capabilities": required(capabilities),
	})(value)
}

func validateCommand(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	kind, ok := value["kind"].(string)
	if !ok {
		return errors.New("kind must be string")
	}
	rule, ok := commandRules[CommandKind(kind)]
	if !ok {
		return fmt.Errorf("unknown command kind %q", kind)
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "commandId": required(uuidCheck), "kind": required(enumCheck(kind)), "target": required(rule.target), "expected": required(rule.expected), "payload": required(rule.payload)})(value)
}

func validateReceipt(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	kind, ok := value["commandKind"].(string)
	if !ok {
		return errors.New("commandKind must be string")
	}
	references, ok := receiptReferences[CommandKind(kind)]
	if !ok {
		return errors.New("unknown receipt command kind")
	}
	result := enumCheck("admitted", "applied")
	if CommandKind(kind) == CommandDialogDelete {
		result = enumCheck("deleted")
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "commandId": required(uuidCheck), "commandKind": required(enumCheck(kind)), "receiptId": required(uuidCheck), "acceptedAt": required(timestampCheck), "nodeId": required(uuidCheck), "eventSeq": required(positiveInteger), "result": required(result), "blockingReason": optional(enumCheck("engine_unavailable", "auth_unavailable", "quota_exhausted", "policy_unavailable", "capability_missing", "storage_unavailable", "execution_unknown", "adapter_protocol", "operator_pause")), "references": required(references)})(value)
}

func validateError(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	if err := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "code": required(enumCheck("invalid", "no_session", "forbidden", "not_found", "stale", "id_conflict", "too_large", "queue_full", "node_unavailable", "not_durable", "unsupported", "protocol_mismatch", "schema_mismatch")), "safeMessage": required(stringCheck(1, 500)), "retryable": required(booleanCheck), "correlationId": required(uuidCheck), "currentVersion": optional(safeInteger), "currentState": optional(enumCheck("queued", "active", "paused", "blocked", "terminal", "unknown"))})(value); err != nil {
		return err
	}
	retryable := value["retryable"].(bool)
	code := value["code"].(string)
	expectedRetryable := code == "queue_full" || code == "node_unavailable" || code == "not_durable"
	if retryable != expectedRetryable {
		return errors.New("error retryability does not match taxonomy")
	}
	return nil
}

func validateEvent(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	typeName, ok := value["type"].(string)
	if !ok {
		return errors.New("event type must be string")
	}
	payload, ok := eventPayloadChecks[typeName]
	if !ok {
		return fmt.Errorf("unknown event type %q", typeName)
	}
	fields := map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "seq": required(positiveInteger), "epoch": required(positiveInteger), "type": required(enumCheck(typeName)), "entityId": required(uuidCheck), "entityVersion": required(safeInteger), "observedAt": required(timestampCheck), "sourceAt": optional(timestampCheck), "completeness": required(enumCheck("complete")), "payload": required(payload)}
	if isAttemptScoped(typeName) {
		fields["attemptId"] = required(uuidCheck)
		fields["dialogId"] = required(uuidCheck)
	} else if typeName == "dialog.deleted" {
		fields["dialogId"] = required(uuidCheck)
	}
	return object(fields)(value)
}

func validateSnapshot(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	pendingRequestCheck := object(map[string]property{"requestId": required(uuidCheck), "dialogId": required(uuidCheck), "inputMessageId": required(uuidCheck), "queueSequence": required(positiveInteger), "version": required(safeInteger), "status": required(enumCheck("queued"))})
	if err := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "stateVersion": required(safeInteger), "lastEventSeq": required(safeInteger), "capturedAt": required(timestampCheck), "node": required(nodeStateCheck), "pendingQueue": required(list(pendingRequestCheck, MaximumPageSize)), "activeAttempt": required(nullable(attemptCheck)), "completeness": required(enumCheck("complete"))})(value); err != nil {
		return err
	}
	node := value["node"].(map[string]any)
	pending := value["pendingQueue"].([]any)
	pendingCount, _ := jsonInteger(node["pendingCount"])
	if pendingCount != int64(len(pending)) {
		return errors.New("pending queue does not match node count")
	}
	requestIDs, messageIDs, sequences := map[string]bool{}, map[string]bool{}, map[int64]bool{}
	var previousSequence int64
	for index, item := range pending {
		request := item.(map[string]any)
		requestID := request["requestId"].(string)
		messageID := request["inputMessageId"].(string)
		sequence, _ := jsonInteger(request["queueSequence"])
		if requestIDs[requestID] || messageIDs[messageID] || sequences[sequence] {
			return errors.New("pending queue identity or sequence is duplicated")
		}
		if index > 0 && sequence <= previousSequence {
			return errors.New("pending queue is not in strict FIFO sequence")
		}
		requestIDs[requestID], messageIDs[messageID], sequences[sequence] = true, true, true
		previousSequence = sequence
	}
	activeID := node["activeAttemptId"]
	active := value["activeAttempt"]
	if active == nil {
		if activeID != nil {
			return errors.New("active attempt does not match node state")
		}
	} else if activeID != active.(map[string]any)["attemptId"] {
		return errors.New("active attempt does not match node state")
	}
	return nil
}

func validatePage(value map[string]any, pageType string, itemCheck check) error {
	if err := validatePins(value); err != nil {
		return err
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "snapshotStateVersion": required(safeInteger), "lastEventSeq": required(safeInteger), "items": required(list(itemCheck, MaximumPageSize)), "nextCursor": required(nullable(stringCheck(1, MaximumCursorBytes))), "pageType": required(enumCheck(pageType))})(value)
}

func validateEventPage(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	rule := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "snapshotStateVersion": required(safeInteger), "lastEventSeq": required(safeInteger), "dialogId": required(uuidCheck), "attemptId": required(uuidCheck), "items": required(list(func(item any) error {
		event, ok := item.(map[string]any)
		if !ok {
			return errors.New("must be event object")
		}
		if typeName, _ := event["type"].(string); !isAttemptScoped(typeName) {
			return errors.New("attempt event page contains node-scoped event")
		}
		return validateEvent(event)
	}, MaximumPageSize)), "nextCursor": required(nullable(stringCheck(1, MaximumCursorBytes))), "pageType": required(enumCheck("events"))})
	if err := rule(value); err != nil {
		return err
	}
	for _, item := range value["items"].([]any) {
		event := item.(map[string]any)
		if event["nodeId"] != value["nodeId"] || event["epoch"] != value["epoch"] || event["dialogId"] != value["dialogId"] || event["attemptId"] != value["attemptId"] {
			return errors.New("event item does not match page scope")
		}
	}
	return nil
}

func validateHistoryPage(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	rule := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "snapshotStateVersion": required(safeInteger), "lastEventSeq": required(safeInteger), "dialogId": required(uuidCheck), "items": required(list(historyCheck, MaximumPageSize)), "nextCursor": required(nullable(stringCheck(1, MaximumCursorBytes))), "pageType": required(enumCheck("history"))})
	if err := rule(value); err != nil {
		return err
	}
	for _, item := range value["items"].([]any) {
		if item.(map[string]any)["dialogId"] != value["dialogId"] {
			return errors.New("history item does not match page scope")
		}
	}
	return nil
}

func validateAttemptPage(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	rule := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "snapshotStateVersion": required(safeInteger), "lastEventSeq": required(safeInteger), "dialogId": required(uuidCheck), "requestId": required(uuidCheck), "items": required(list(attemptCheck, MaximumPageSize)), "nextCursor": required(nullable(stringCheck(1, MaximumCursorBytes))), "pageType": required(enumCheck("attempts"))})
	if err := rule(value); err != nil {
		return err
	}
	for _, item := range value["items"].([]any) {
		attempt := item.(map[string]any)
		if attempt["dialogId"] != value["dialogId"] || attempt["requestId"] != value["requestId"] {
			return errors.New("attempt item does not match page scope")
		}
	}
	return nil
}

var capabilityStatusCheck = enumCheck("unsupported", "declared", "verified")
var capabilitiesCheck = object(map[string]property{"chat": required(capabilityStatusCheck), "events": required(capabilityStatusCheck), "tool_results": required(capabilityStatusCheck), "cancel": required(capabilityStatusCheck), "steer_attached": required(capabilityStatusCheck), "session_resume": required(capabilityStatusCheck), "policy_enforcement": required(capabilityStatusCheck)})
var adapterIdentityCheck = union(
	object(map[string]property{"kind": required(enumCheck("cursor")), "version": required(enumCheck("1.0.31"))}),
	object(map[string]property{"kind": required(enumCheck("codex")), "version": required(enumCheck("0.153.4"))}),
)

func validateNodeIdentity(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "schemaSHA256": required(schemaSHA256Check), "nodeId": required(uuidCheck), "registryVersion": required(safeInteger), "identityEpoch": required(positiveInteger), "adapter": required(adapterIdentityCheck), "capabilities": required(capabilitiesCheck)})(value)
}

func validateAttemptRead(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "epoch": required(positiveInteger), "stateVersion": required(safeInteger), "attempt": required(attemptCheck)})(value)
}

func validateCommandStatus(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	if err := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "commandId": required(uuidCheck), "canonicalPayloadHash": required(sha256Check), "status": required(enumCheck("accepted")), "receipt": required(func(value any) error {
		receipt, ok := value.(map[string]any)
		if !ok {
			return errors.New("must be receipt object")
		}
		return validateReceipt(receipt)
	})})(value); err != nil {
		return err
	}
	receipt := value["receipt"].(map[string]any)
	if receipt["nodeId"] != value["nodeId"] || receipt["commandId"] != value["commandId"] {
		return errors.New("receipt does not match command status scope")
	}
	return nil
}

func validateHealthLive(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "status": required(enumCheck("live")), "processStartedAt": required(timestampCheck)})(value)
}

func validateHealthReady(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	rule := object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "checkedAt": required(timestampCheck), "identity": required(func(value any) error {
		identity, ok := value.(map[string]any)
		if !ok {
			return errors.New("must be identity object")
		}
		return validateNodeIdentity(identity)
	}), "readiness": required(enumCheck("ready", "blocked", "unknown")), "blockedReasons": required(list(enumCheck("engine_unavailable", "auth_unavailable", "quota_exhausted", "policy_unavailable", "capability_missing", "storage_unavailable", "execution_unknown", "adapter_protocol", "operator_pause"), 16))})
	if err := rule(value); err != nil {
		return err
	}
	if value["readiness"] == "ready" {
		if len(value["blockedReasons"].([]any)) != 0 {
			return errors.New("ready health has blocked reasons")
		}
		capabilities := value["identity"].(map[string]any)["capabilities"].(map[string]any)
		for _, status := range capabilities {
			if status != "verified" {
				return errors.New("ready health has unverified capability")
			}
		}
	}
	return nil
}

func validateArtifactMetadata(value map[string]any) error {
	if err := validatePins(value); err != nil {
		return err
	}
	return object(map[string]property{"protocolVersion": required(safeInteger), "schemaId": required(stringCheck(1, 100)), "nodeId": required(uuidCheck), "dialogId": required(uuidCheck), "attemptId": required(uuidCheck), "artifactId": required(uuidCheck), "callId": optional(uuidCheck), "name": required(stringCheck(1, 200)), "mediaType": required(stringCheck(1, 200)), "sizeBytes": required(integerCheck(false, MaximumArtifactBytes)), "sha256": required(sha256Check), "redaction": required(enumCheck("none", "applied")), "truncated": required(booleanCheck), "disposition": required(enumCheck("inline", "attachment"))})(value)
}

func validatePins(value map[string]any) error {
	protocol, ok := jsonInteger(value["protocolVersion"])
	if !ok || protocol != ProtocolVersion {
		return errors.New("protocolVersion mismatch")
	}
	schema, ok := value["schemaId"].(string)
	if !ok || schema != SchemaID {
		return errors.New("schemaId mismatch")
	}
	return nil
}

func DecodeCommand(data []byte) (any, error) {
	if err := Validate("command", data); err != nil {
		return nil, err
	}
	var envelope CommandEnvelope
	if err := decode(data, &envelope); err != nil {
		return nil, err
	}
	switch envelope.Kind {
	case CommandDialogCreate:
		var result DialogCreateCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandDialogDelete:
		var result DialogDeleteCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandMessageEnqueue:
		var result MessageEnqueueCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandMessageSteer:
		var result MessageSteerCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandRequestCancel:
		var result RequestCancelCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandAttemptStop:
		var result AttemptStopCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandQueueResume:
		var result QueueResumeCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandAttemptRetry:
		var result AttemptRetryCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandApprovalRespond:
		var result ApprovalRespondCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	case CommandInputRespond:
		var result InputRespondCommand
		result.Envelope = envelope
		return result, decodeParts(envelope, &result.Target, &result.Expected, &result.Payload)
	default:
		return nil, errors.New("unknown command kind")
	}
}

type TypedReceipt struct {
	Receipt    Receipt
	References any
}

func DecodeReceipt(data []byte) (TypedReceipt, error) {
	if err := Validate("receipt", data); err != nil {
		return TypedReceipt{}, err
	}
	var receipt Receipt
	if err := decode(data, &receipt); err != nil {
		return TypedReceipt{}, err
	}
	constructors := map[CommandKind]func() any{
		CommandDialogCreate: func() any { return &DialogCreateReferences{} }, CommandMessageEnqueue: func() any { return &MessageEnqueueReferences{} },
		CommandDialogDelete: func() any { return &DialogDeleteReferences{} },
		CommandMessageSteer: func() any { return &MessageSteerReferences{} }, CommandRequestCancel: func() any { return &RequestCancelReferences{} },
		CommandAttemptStop: func() any { return &AttemptStopReferences{} }, CommandQueueResume: func() any { return &QueueResumeReferences{} },
		CommandAttemptRetry: func() any { return &AttemptRetryReferences{} }, CommandApprovalRespond: func() any { return &ApprovalRespondReferences{} },
		CommandInputRespond: func() any { return &InputRespondReferences{} },
	}
	references := constructors[receipt.CommandKind]()
	if err := decode(receipt.References, references); err != nil {
		return TypedReceipt{}, err
	}
	return TypedReceipt{Receipt: receipt, References: references}, nil
}

type TypedEvent struct {
	Envelope EventEnvelope
	Payload  any
}

func DecodeEvent(data []byte) (TypedEvent, error) {
	if err := Validate("event", data); err != nil {
		return TypedEvent{}, err
	}
	var envelope EventEnvelope
	if err := decode(data, &envelope); err != nil {
		return TypedEvent{}, err
	}
	constructors := map[string]func() any{
		"node.state_changed": func() any { return &NodeStateChangedPayload{} }, "dialog.deleted": func() any { return &DialogDeletedPayload{} }, "queue.changed": func() any { return &QueueChangedPayload{} }, "message.accepted": func() any { return &MessageAcceptedPayload{} }, "message.disposition_changed": func() any { return &MessageDispositionPayload{} },
		"attempt.dispatching": func() any { return &AttemptDispatchingPayload{} }, "attempt.started": func() any { return &AttemptStartedPayload{} }, "attempt.waiting_input": func() any { return &AttemptWaitingPayload{} }, "attempt.stop_requested": func() any { return &AttemptStopRequestedPayload{} }, "attempt.completed": func() any { return &AttemptCompletedPayload{} }, "attempt.failed": func() any { return &AttemptFailedPayload{} }, "attempt.interrupted": func() any { return &AttemptInterruptedPayload{} }, "attempt.unknown": func() any { return &AttemptUnknownPayload{} },
		"assistant.delta": func() any { return &AssistantDeltaPayload{} }, "assistant.message": func() any { return &AssistantMessagePayload{} }, "tool.started": func() any { return &ToolStartedPayload{} }, "tool.output": func() any { return &ToolOutputPayload{} }, "tool.completed": func() any { return &ToolCompletedPayload{} }, "approval.requested": func() any { return &ApprovalRequestedPayload{} }, "approval.resolved": func() any { return &ApprovalResolvedPayload{} }, "input.requested": func() any { return &InputRequestedPayload{} }, "input.resolved": func() any { return &InputResolvedPayload{} }, "artifact.available": func() any { return &ArtifactAvailablePayload{} }, "history.gap": func() any { return &HistoryGapPayload{} },
	}
	payload := constructors[envelope.Type]()
	if err := decode(envelope.Payload, payload); err != nil {
		return TypedEvent{}, err
	}
	return TypedEvent{Envelope: envelope, Payload: payload}, nil
}

func decodeObject(data []byte) (map[string]any, error) {
	if len(data) > MaximumWireBytes {
		return nil, errors.New("wire JSON exceeds 8 MiB")
	}
	if !strictjson.Valid(data) {
		return nil, errors.New("malformed, non-UTF-8 or duplicate-key JSON")
	}
	var value map[string]any
	if err := decode(data, &value); err != nil || value == nil {
		return nil, errors.New("wire value must be object")
	}
	return value, nil
}

func decode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func decodeParts(envelope CommandEnvelope, target, expected, payload any) error {
	for _, part := range []struct {
		data   []byte
		target any
	}{{envelope.Target, target}, {envelope.Expected, expected}, {envelope.Payload, payload}} {
		if err := decode(part.data, part.target); err != nil {
			return err
		}
	}
	return nil
}

func jsonInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	if !integerPattern.MatchString(number.String()) {
		return 0, false
	}
	result, err := number.Int64()
	return result, err == nil
}

func isAttemptScoped(eventType string) bool {
	for _, prefix := range []string{"attempt.", "assistant.", "tool.", "approval.", "input."} {
		if len(eventType) >= len(prefix) && eventType[:len(prefix)] == prefix {
			return true
		}
	}
	return eventType == "artifact.available"
}
