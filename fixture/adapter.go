// Package fixture provides a deterministic, provider-free adapter for B1 tests.
package fixture

import (
	"context"
	"errors"
	"sync"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

// Adapter records calls and returns outcomes selected by the test. It never
// starts a provider process or makes a network request.
type Adapter struct {
	mu sync.Mutex

	AdapterIdentity harnessadapter.Identity
	StartResult     harnessadapter.StartResult
	ResumeResult    harnessadapter.ResumeResult
	SteerResult     harnessadapter.SteerResult
	CancelResult    harnessadapter.CancelResult
	ApprovalResult  harnessadapter.ResponseResult
	InputResult     harnessadapter.ResponseResult
	ReconcileResult harnessadapter.ReconcileResult
	StreamEvents    []harnessadapter.Event
	StreamInput     <-chan harnessadapter.Event
	StreamEOF       bool
	StreamError     error
	Calls           []Call
	StartGate       <-chan struct{}
	ResumeGate      <-chan struct{}
	CancelGate      <-chan struct{}
	SteerGate       <-chan struct{}
	EventsGate      <-chan struct{}
	StartCalled     chan<- struct{}
	ResumeCalled    chan<- struct{}
	CancelCalled    chan<- struct{}
	SteerCalled     chan<- struct{}
	EventsCalled    chan<- struct{}
}

type Call struct {
	Method  string
	Attempt harnessadapter.AttemptRef
	Context harnessadapter.ContextBoundary
}

func NewAdapter() *Adapter {
	declared := make(map[harnessadapter.Capability]bool)
	verified := make(map[harnessadapter.Capability]bool)
	for _, capability := range []harnessadapter.Capability{
		harnessadapter.CapabilityChat,
		harnessadapter.CapabilityEvents,
		harnessadapter.CapabilityToolResults,
		harnessadapter.CapabilityCancel,
		harnessadapter.CapabilitySteerAttached,
		harnessadapter.CapabilitySessionResume,
		harnessadapter.CapabilityPolicyEnforcement,
	} {
		declared[capability] = true
		verified[capability] = true
	}
	return &Adapter{
		AdapterIdentity: harnessadapter.Identity{
			Kind: harnessadapter.KindCodex, Version: harnessadapter.CodexAppServerVersion,
			ProtocolVersion: harnessprotocol.ProtocolVersion, SchemaID: harnessprotocol.SchemaID,
			SchemaSHA256: harnessprotocol.SchemaSHA256, Declared: declared, Verified: verified,
		},
		StartResult:     harnessadapter.StartResult{Outcome: harnessadapter.StartStarted},
		ResumeResult:    harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeStarted},
		SteerResult:     harnessadapter.SteerResult{Outcome: harnessadapter.SteerApplied},
		CancelResult:    harnessadapter.CancelResult{Outcome: harnessadapter.CancelAcknowledged},
		ApprovalResult:  harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseApplied},
		InputResult:     harnessadapter.ResponseResult{Outcome: harnessadapter.ResponseApplied},
		ReconcileResult: harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileRunning},
	}
}

func (adapter *Adapter) Identity(context.Context) (harnessadapter.Identity, error) {
	return adapter.AdapterIdentity, nil
}

func (adapter *Adapter) record(method string, attempt harnessadapter.AttemptRef) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.Calls = append(adapter.Calls, Call{Method: method, Attempt: attempt})
}

func (adapter *Adapter) Start(ctx context.Context, input harnessadapter.StartInput) (harnessadapter.StartResult, error) {
	adapter.mu.Lock()
	adapter.Calls = append(adapter.Calls, Call{Method: "start", Attempt: input.Attempt, Context: input.Context})
	adapter.mu.Unlock()
	if adapter.StartCalled != nil {
		select {
		case adapter.StartCalled <- struct{}{}:
		default:
		}
	}
	if adapter.StartGate != nil {
		select {
		case <-adapter.StartGate:
		case <-ctx.Done():
			return harnessadapter.StartResult{Outcome: harnessadapter.StartUnknown}, ctx.Err()
		}
	}
	return adapter.StartResult, nil
}

func (adapter *Adapter) Resume(ctx context.Context, input harnessadapter.ResumeInput) (harnessadapter.ResumeResult, error) {
	adapter.mu.Lock()
	adapter.Calls = append(adapter.Calls, Call{Method: "resume", Attempt: input.Attempt, Context: input.Context})
	adapter.mu.Unlock()
	if adapter.ResumeCalled != nil {
		select {
		case adapter.ResumeCalled <- struct{}{}:
		default:
		}
	}
	if adapter.ResumeGate != nil {
		select {
		case <-adapter.ResumeGate:
		case <-ctx.Done():
			return harnessadapter.ResumeResult{Outcome: harnessadapter.ResumeUnknown}, ctx.Err()
		}
	}
	return adapter.ResumeResult, nil
}

func (adapter *Adapter) Events(ctx context.Context, input harnessadapter.EventsInput) (harnessadapter.EventStream, error) {
	adapter.record("events", input.Attempt)
	if adapter.EventsCalled != nil {
		select {
		case adapter.EventsCalled <- struct{}{}:
		default:
		}
	}
	if adapter.EventsGate != nil {
		select {
		case <-adapter.EventsGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	adapter.mu.Lock()
	events := append([]harnessadapter.Event(nil), adapter.StreamEvents...)
	streamInput, endOfStream, streamError := adapter.StreamInput, adapter.StreamEOF, adapter.StreamError
	adapter.mu.Unlock()
	return newEventStream(events, streamInput, endOfStream, streamError), nil
}

func (adapter *Adapter) Steer(ctx context.Context, input harnessadapter.SteerInput) (harnessadapter.SteerResult, error) {
	adapter.record("steer", input.Attempt)
	if adapter.SteerCalled != nil {
		select {
		case adapter.SteerCalled <- struct{}{}:
		default:
		}
	}
	if adapter.SteerGate != nil {
		select {
		case <-adapter.SteerGate:
		case <-ctx.Done():
			return harnessadapter.SteerResult{Outcome: harnessadapter.SteerUnknown}, ctx.Err()
		}
	}
	return adapter.SteerResult, nil
}

func (adapter *Adapter) Cancel(ctx context.Context, input harnessadapter.CancelInput) (harnessadapter.CancelResult, error) {
	adapter.record("cancel", input.Attempt)
	if adapter.CancelCalled != nil {
		select {
		case adapter.CancelCalled <- struct{}{}:
		default:
		}
	}
	if adapter.CancelGate != nil {
		select {
		case <-adapter.CancelGate:
		case <-ctx.Done():
			return harnessadapter.CancelResult{Outcome: harnessadapter.CancelUnknown}, ctx.Err()
		}
	}
	return adapter.CancelResult, nil
}

func (adapter *Adapter) CallsSnapshot() []Call {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]Call(nil), adapter.Calls...)
}

func (adapter *Adapter) RespondApproval(_ context.Context, input harnessadapter.RespondApprovalInput) (harnessadapter.ResponseResult, error) {
	adapter.record("approval", input.Attempt)
	return adapter.ApprovalResult, nil
}

func (adapter *Adapter) RespondInput(_ context.Context, input harnessadapter.RespondInputInput) (harnessadapter.ResponseResult, error) {
	adapter.record("input", input.Attempt)
	return adapter.InputResult, nil
}

func (adapter *Adapter) Reconcile(_ context.Context, input harnessadapter.ReconcileInput) (harnessadapter.ReconcileResult, error) {
	adapter.record("reconcile", input.Attempt)
	return adapter.ReconcileResult, nil
}

var ErrInjected = errors.New("fixture adapter failure")
