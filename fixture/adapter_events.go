package fixture

import (
	"context"
	"io"
	"sync"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

type eventStream struct {
	mu        sync.Mutex
	events    []harnessadapter.Event
	input     <-chan harnessadapter.Event
	eof       bool
	err       error
	index     int
	closed    chan struct{}
	closeOnce sync.Once
}

func newEventStream(events []harnessadapter.Event, input <-chan harnessadapter.Event, eof bool, err error) *eventStream {
	return &eventStream{events: events, input: input, eof: eof, err: err, closed: make(chan struct{})}
}

func (stream *eventStream) Next(ctx context.Context) (harnessadapter.Event, error) {
	stream.mu.Lock()
	if stream.index < len(stream.events) {
		event := stream.events[stream.index]
		stream.index++
		stream.mu.Unlock()
		return event, nil
	}
	if stream.err != nil {
		err := stream.err
		stream.err = nil
		stream.mu.Unlock()
		return nil, err
	}
	if stream.eof {
		stream.mu.Unlock()
		return nil, io.EOF
	}
	input := stream.input
	stream.mu.Unlock()

	if input == nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stream.closed:
			return nil, io.EOF
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-stream.closed:
		return nil, io.EOF
	case event, ok := <-input:
		if !ok {
			return nil, io.EOF
		}
		return event, nil
	}
}

func (stream *eventStream) Close() error {
	stream.closeOnce.Do(func() { close(stream.closed) })
	return nil
}
