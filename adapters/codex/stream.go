package codex

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const maximumQueuedEvents = 1024
const maximumQueuedDeltaBytes = harnessprotocol.MaximumMessageBytes / 16

type attemptRuntime struct {
	mu        sync.Mutex
	reference harnessadapter.AttemptRef
	events    []harnessadapter.Event
	pending   []harnessadapter.Event
	wake      chan struct{}
	activated bool
	closed    bool
	claimed   bool
	err       error
	terminal  *harnessadapter.ReconcileResult
	waiting   int
	deltas    map[string]int64
}

func newAttemptRuntime(reference harnessadapter.AttemptRef) *attemptRuntime {
	return &attemptRuntime{reference: reference, wake: make(chan struct{}, 1), deltas: make(map[string]int64)}
}

func (runtime *attemptRuntime) activate() {
	runtime.mu.Lock()
	if runtime.activated {
		runtime.mu.Unlock()
		return
	}
	runtime.activated = true
	if runtime.err != nil {
		runtime.signalLocked()
		runtime.mu.Unlock()
		return
	}
	runtime.enqueueLocked(harnessadapter.StartedEvent{EventBase: harnessadapter.EventBase{Attempt: runtime.reference}})
	if len(runtime.events)+len(runtime.pending) > maximumQueuedEvents {
		runtime.overflowLocked()
	} else {
		runtime.events = append(runtime.events, runtime.pending...)
	}
	runtime.pending = nil
	runtime.signalLocked()
	runtime.mu.Unlock()
}

func (runtime *attemptRuntime) push(event harnessadapter.Event) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return
	}
	if event == nil || event.AttemptReference() != runtime.reference {
		runtime.overflowLocked()
		return
	}
	if !runtime.activated {
		runtime.pending = runtime.appendEventLocked(runtime.pending, event)
		if len(runtime.pending) > maximumQueuedEvents {
			runtime.overflowLocked()
		}
		return
	}
	runtime.enqueueLocked(event)
	runtime.signalLocked()
}

func (runtime *attemptRuntime) enqueueLocked(event harnessadapter.Event) {
	runtime.events = runtime.appendEventLocked(runtime.events, event)
	if len(runtime.events) > maximumQueuedEvents {
		runtime.overflowLocked()
		return
	}
}

func (runtime *attemptRuntime) appendEventLocked(queue []harnessadapter.Event, event harnessadapter.Event) []harnessadapter.Event {
	delta, ok := event.(harnessadapter.AssistantDeltaEvent)
	if !ok {
		return append(queue, event)
	}
	if len(queue) > 0 {
		previous, compatible := queue[len(queue)-1].(harnessadapter.AssistantDeltaEvent)
		if compatible && previous.MessageID == delta.MessageID && previous.Content.Kind == "inline" &&
			delta.Content.Kind == "inline" && previous.Content.Redaction == delta.Content.Redaction &&
			!previous.Content.Truncated && !delta.Content.Truncated &&
			len(previous.Content.Content)+len(delta.Content.Content) <= maximumQueuedDeltaBytes {
			previous.Content.Content += delta.Content.Content
			queue[len(queue)-1] = previous
			return queue
		}
	}
	delta.DeltaIndex = runtime.deltas[delta.MessageID]
	runtime.deltas[delta.MessageID]++
	return append(queue, delta)
}

func (runtime *attemptRuntime) overflowLocked() {
	runtime.pending = nil
	runtime.events = []harnessadapter.Event{harnessadapter.UnknownEvent{
		EventBase: harnessadapter.EventBase{Attempt: runtime.reference}, Reason: "adapter_protocol", EffectStatus: "unknown",
	}}
	result := harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown, EffectStatus: "unknown"}
	runtime.terminal = &result
	runtime.err = errors.New("codex event queue limit exceeded")
	runtime.closed = true
	runtime.signalLocked()
}

func (runtime *attemptRuntime) finish(result harnessadapter.ReconcileResult, events ...harnessadapter.Event) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return
	}
	for _, event := range events {
		if event == nil || event.AttemptReference() != runtime.reference {
			runtime.overflowLocked()
			return
		}
		if runtime.activated {
			runtime.enqueueLocked(event)
			if runtime.err != nil {
				return
			}
		} else {
			runtime.pending = runtime.appendEventLocked(runtime.pending, event)
			if len(runtime.pending) > maximumQueuedEvents {
				runtime.overflowLocked()
				return
			}
		}
	}
	if runtime.closed {
		return
	}
	runtime.terminal = &result
	runtime.closed = true
	runtime.signalLocked()
}

func (runtime *attemptRuntime) failUnknown(reason string) {
	result := harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileUnknown, EffectStatus: "unknown"}
	runtime.finish(result, harnessadapter.UnknownEvent{
		EventBase: harnessadapter.EventBase{Attempt: runtime.reference}, Reason: reason, EffectStatus: "unknown",
	})
}

func (runtime *attemptRuntime) signalLocked() {
	select {
	case runtime.wake <- struct{}{}:
	default:
	}
}

func (runtime *attemptRuntime) claim() (*eventStream, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.claimed {
		return nil, errors.New("codex event stream is already claimed")
	}
	runtime.claimed = true
	return &eventStream{runtime: runtime}, nil
}

func (runtime *attemptRuntime) reconcile() harnessadapter.ReconcileResult {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.terminal != nil {
		return *runtime.terminal
	}
	if runtime.waiting > 0 {
		return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileWaitingInput, EffectStatus: "known"}
	}
	return harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileRunning, EffectStatus: "known"}
}

func (runtime *attemptRuntime) setWaitingInput(waiting bool) {
	runtime.mu.Lock()
	if waiting {
		runtime.waiting++
	} else if runtime.waiting > 0 {
		runtime.waiting--
	}
	runtime.mu.Unlock()
}

type eventStream struct {
	runtime *attemptRuntime
	once    sync.Once
	closed  chan struct{}
}

func (stream *eventStream) closeChannel() chan struct{} {
	stream.once.Do(func() { stream.closed = make(chan struct{}) })
	return stream.closed
}

func (stream *eventStream) Next(ctx context.Context) (harnessadapter.Event, error) {
	closed := stream.closeChannel()
	for {
		stream.runtime.mu.Lock()
		if len(stream.runtime.events) > 0 {
			event := stream.runtime.events[0]
			stream.runtime.events = stream.runtime.events[1:]
			stream.runtime.mu.Unlock()
			return event, nil
		}
		ended, streamErr := stream.runtime.closed, stream.runtime.err
		stream.runtime.mu.Unlock()
		if ended {
			if streamErr != nil {
				return nil, streamErr
			}
			return nil, io.EOF
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-closed:
			return nil, io.EOF
		case <-stream.runtime.wake:
		}
	}
}

func (stream *eventStream) Close() error {
	closed := stream.closeChannel()
	select {
	case <-closed:
	default:
		close(closed)
	}
	return nil
}
