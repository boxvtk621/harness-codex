// Package diagnosticlog emits bounded, metadata-only operational events.
// It deliberately has no free-form message or error field: provider output,
// prompts, message content, tool payloads, paths and raw exceptions do not
// belong in the diagnostic stream.
package diagnosticlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	Schema         = "harness.console.v1"
	QueueCapacity  = 256
	MaximumRecord  = 4 << 10
	maximumIDBytes = 128
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Component string

const (
	ComponentService  Component = "service"
	ComponentRuntime  Component = "runtime"
	ComponentProvider Component = "provider"
	ComponentLogger   Component = "logger"
	ComponentAPI      Component = "api"
)

type Event string

const (
	EventLogDropped            Event = "log.records_dropped"
	EventLogWriteError         Event = "log.write_failed"
	EventServiceStarting       Event = "service.starting"
	EventServiceStopped        Event = "service.stopped"
	EventServiceFailed         Event = "service.failed"
	EventRecoveryStarted       Event = "recovery.started"
	EventRecoveryComplete      Event = "recovery.completed"
	EventRecoveryFailed        Event = "recovery.failed"
	EventProviderReady         Event = "provider.process_ready"
	EventProviderExited        Event = "provider.process_exited"
	EventRuntimeOpened         Event = "runtime.opened"
	EventRuntimeRecovered      Event = "runtime.recovered"
	EventRuntimeClosed         Event = "runtime.closed"
	EventAttemptDispatch       Event = "attempt.dispatching"
	EventAttemptStarted        Event = "attempt.started"
	EventAttemptTerminal       Event = "attempt.terminal"
	EventAttemptUnknown        Event = "attempt.unknown"
	EventToolStarted           Event = "tool.started"
	EventToolCompleted         Event = "tool.completed"
	EventCommandFailed         Event = "command.failed"
	EventCommandAccepted       Event = "command.accepted"
	EventCommandRejected       Event = "command.rejected"
	EventCommandDuplicate      Event = "command.deduplicated"
	EventProviderAuthStarted   Event = "provider.auth_started"
	EventProviderAuthCompleted Event = "provider.auth_completed"
	EventProviderAuthCancelled Event = "provider.auth_cancelled"
	EventProviderAuthExpired   Event = "provider.auth_expired"
	EventProviderAuthFailed    Event = "provider.auth_failed"
	EventProviderAuthLogout    Event = "provider.auth_logout"
	EventReadinessChanged      Event = "readiness.changed"
)

var allowedEvents = map[Event]struct{}{
	EventLogDropped: {}, EventLogWriteError: {}, EventServiceStarting: {}, EventServiceStopped: {}, EventServiceFailed: {},
	EventRecoveryStarted: {}, EventRecoveryComplete: {}, EventRecoveryFailed: {},
	EventProviderReady: {}, EventProviderExited: {}, EventRuntimeOpened: {}, EventRuntimeRecovered: {}, EventRuntimeClosed: {},
	EventAttemptDispatch: {}, EventAttemptStarted: {}, EventAttemptTerminal: {}, EventAttemptUnknown: {},
	EventToolStarted: {}, EventToolCompleted: {}, EventCommandFailed: {},
	EventCommandAccepted: {}, EventCommandRejected: {}, EventCommandDuplicate: {},
	EventProviderAuthStarted: {}, EventProviderAuthCompleted: {}, EventProviderAuthCancelled: {},
	EventProviderAuthExpired: {}, EventProviderAuthFailed: {}, EventProviderAuthLogout: {}, EventReadinessChanged: {},
}

var tokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Fields is the complete field allowlist. Values are identifiers, bounded
// enum-like tokens, counters or booleans; no user-controlled text is accepted.
type Fields struct {
	NodeID            string
	DialogID          string
	RequestID         string
	AttemptID         string
	CallID            string
	CommandID         string
	OperationID       string
	Generation        int64
	ProcessGeneration int64
	Kind              string
	Operation         string
	Outcome           string
	Reason            string
	Tool              string
	EffectStatus      string
	Truncated         bool
	DurationMS        int64
	Count             uint64
}

type Sink interface {
	Emit(Level, Event, Fields)
	SetNodeID(string)
}

type nopSink struct{}

func (nopSink) Emit(Level, Event, Fields) {}
func (nopSink) SetNodeID(string)          {}

func Nop() Sink { return nopSink{} }

type Config struct {
	Writer    io.Writer
	Component string
	Clock     func() time.Time
}

type Logger struct {
	writer    io.Writer
	component string
	clock     func() time.Time
	bootID    string
	queue     chan []byte
	dropped   atomic.Uint64
	failures  atomic.Uint64
	closeMu   sync.RWMutex
	closed    bool
	done      chan struct{}
	nodeMu    sync.RWMutex
	nodeID    string
}

type record struct {
	Schema            string    `json:"schema"`
	Timestamp         string    `json:"ts"`
	BootID            string    `json:"bootId"`
	Level             Level     `json:"level"`
	Component         Component `json:"component"`
	Event             Event     `json:"event"`
	NodeID            string    `json:"nodeId"`
	DialogID          string    `json:"dialogId,omitempty"`
	RequestID         string    `json:"requestId,omitempty"`
	AttemptID         string    `json:"attemptId,omitempty"`
	CallID            string    `json:"toolCallId,omitempty"`
	CommandID         string    `json:"commandId,omitempty"`
	OperationID       string    `json:"operationId,omitempty"`
	Generation        int64     `json:"generation,omitempty"`
	ProcessGeneration int64     `json:"processGeneration,omitempty"`
	Kind              string    `json:"kind,omitempty"`
	Operation         string    `json:"operation,omitempty"`
	Outcome           string    `json:"outcome,omitempty"`
	Reason            string    `json:"reasonCode,omitempty"`
	Explanation       string    `json:"explanation,omitempty"`
	Tool              string    `json:"tool,omitempty"`
	EffectStatus      string    `json:"effectStatus,omitempty"`
	Truncated         bool      `json:"truncated,omitempty"`
	Count             uint64    `json:"count,omitempty"`
	DurationMS        int64     `json:"durationMs,omitempty"`
}

func New(config Config) *Logger {
	if config.Writer == nil {
		config.Writer = io.Discard
	}
	if !tokenPattern.MatchString(config.Component) {
		config.Component = "harness-codex"
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	logger := &Logger{writer: config.Writer, component: config.Component, clock: config.Clock, bootID: newBootID(), queue: make(chan []byte, QueueCapacity), done: make(chan struct{})}
	go logger.run()
	return logger
}

// SetNodeID installs the validated node identity used by all subsequent
// records, including internal loss summaries.
func (logger *Logger) SetNodeID(nodeID string) {
	if logger == nil || !validID(nodeID) {
		return
	}
	logger.nodeMu.Lock()
	logger.nodeID = nodeID
	logger.nodeMu.Unlock()
}

func (logger *Logger) Emit(level Level, event Event, fields Fields) {
	if logger != nil && fields.NodeID == "" {
		logger.nodeMu.RLock()
		fields.NodeID = logger.nodeID
		logger.nodeMu.RUnlock()
	}
	if logger == nil || !validLevel(level) || !validEvent(event) || !validFields(fields) {
		if logger != nil {
			logger.dropped.Add(1)
		}
		return
	}
	encoded, ok := logger.encode(level, event, fields, 0)
	if !ok {
		logger.dropped.Add(1)
		return
	}
	logger.closeMu.RLock()
	defer logger.closeMu.RUnlock()
	if logger.closed {
		return
	}
	select {
	case logger.queue <- encoded:
	default:
		logger.dropped.Add(1)
	}
}

func (logger *Logger) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = logger.Shutdown(ctx)
}

func (logger *Logger) Shutdown(ctx context.Context) error {
	if logger == nil {
		return nil
	}
	logger.closeMu.Lock()
	if logger.closed {
		logger.closeMu.Unlock()
		select {
		case <-logger.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	logger.closed = true
	close(logger.queue)
	logger.closeMu.Unlock()
	select {
	case <-logger.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (logger *Logger) run() {
	defer close(logger.done)
	for encoded := range logger.queue {
		logger.writeFailureSummary()
		logger.writeDropSummary()
		if written, err := logger.writer.Write(encoded); err != nil || written != len(encoded) {
			logger.failures.Add(1)
		}
	}
	logger.writeDropSummary()
	logger.writeFailureSummary()
}

func (logger *Logger) writeFailureSummary() {
	failed := logger.failures.Swap(0)
	if failed == 0 {
		return
	}
	logger.nodeMu.RLock()
	nodeID := logger.nodeID
	logger.nodeMu.RUnlock()
	if nodeID == "" {
		return
	}
	encoded, ok := logger.encode(LevelWarn, EventLogWriteError, Fields{NodeID: nodeID, Count: failed}, 0)
	if !ok {
		return
	}
	if written, err := logger.writer.Write(encoded); err != nil || written != len(encoded) {
		logger.failures.Add(failed)
	}
}

func (logger *Logger) writeDropSummary() {
	dropped := logger.dropped.Swap(0)
	if dropped == 0 {
		return
	}
	logger.nodeMu.RLock()
	nodeID := logger.nodeID
	logger.nodeMu.RUnlock()
	if nodeID == "" {
		return
	}
	encoded, ok := logger.encode(LevelWarn, EventLogDropped, Fields{NodeID: nodeID}, dropped)
	if !ok {
		return
	}
	if written, err := logger.writer.Write(encoded); err != nil || written != len(encoded) {
		logger.dropped.Add(dropped)
		logger.failures.Add(1)
	}
}

func (logger *Logger) encode(level Level, event Event, fields Fields, dropped uint64) ([]byte, bool) {
	value := record{
		Schema: Schema, Timestamp: logger.clock().UTC().Format(time.RFC3339Nano), BootID: logger.bootID, Level: level, Component: componentForEvent(event), Event: event,
		NodeID: fields.NodeID, DialogID: fields.DialogID, RequestID: fields.RequestID, AttemptID: fields.AttemptID, CallID: fields.CallID,
		CommandID: fields.CommandID, OperationID: fields.OperationID,
		Generation: fields.Generation, ProcessGeneration: fields.ProcessGeneration, Kind: fields.Kind, Operation: fields.Operation, Outcome: fields.Outcome,
		Reason: fields.Reason, Explanation: terminalExplanation(event, fields), Tool: fields.Tool, EffectStatus: fields.EffectStatus, Truncated: fields.Truncated, Count: fields.Count + dropped, DurationMS: fields.DurationMS,
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaximumRecord {
		return nil, false
	}
	return append(encoded, '\n'), true
}

func validLevel(level Level) bool {
	return level == LevelDebug || level == LevelInfo || level == LevelWarn || level == LevelError
}

func validEvent(event Event) bool {
	_, ok := allowedEvents[event]
	return ok
}

func validFields(fields Fields) bool {
	if !validID(fields.NodeID) {
		return false
	}
	for _, id := range []string{fields.NodeID, fields.DialogID, fields.RequestID, fields.AttemptID, fields.CallID, fields.CommandID, fields.OperationID} {
		if id != "" && (!utf8.ValidString(id) || len(id) > maximumIDBytes || !tokenPattern.MatchString(id)) {
			return false
		}
	}
	for _, token := range []string{fields.Kind, fields.Operation, fields.Outcome, fields.Reason, fields.Tool, fields.EffectStatus} {
		if token != "" && !tokenPattern.MatchString(token) {
			return false
		}
	}
	return fields.Generation >= 0 && fields.ProcessGeneration >= 0 && fields.DurationMS >= 0
}

func componentForEvent(event Event) Component {
	switch event {
	case EventServiceStarting, EventServiceStopped, EventServiceFailed, EventRecoveryStarted, EventRecoveryComplete, EventRecoveryFailed:
		return ComponentService
	case EventProviderReady, EventProviderExited, EventToolStarted, EventToolCompleted:
		return ComponentProvider
	case EventProviderAuthStarted, EventProviderAuthCompleted, EventProviderAuthCancelled, EventProviderAuthExpired, EventProviderAuthFailed, EventProviderAuthLogout, EventReadinessChanged:
		return ComponentAPI
	case EventLogDropped, EventLogWriteError:
		return ComponentLogger
	default:
		return ComponentRuntime
	}
}

func validID(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= maximumIDBytes && tokenPattern.MatchString(value)
}

func newBootID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(raw[:])
}

// Only fixed, reviewed text is emitted; provider diagnostics never enter Fields.
func terminalExplanation(event Event, fields Fields) string {
	if event != EventAttemptTerminal {
		return ""
	}
	if fields.Reason == "codex_model_unsupported" {
		return "Configured Codex model is unavailable for this account. Select an entitled model, then explicitly retry the failed message."
	}
	if fields.Outcome == "failed" {
		return "Attempt failed. Inspect its durable events and effect status before retrying."
	}
	if fields.Outcome == "interrupted" {
		return "Attempt interrupted. Check effect status before retrying."
	}
	return ""
}
