package fixture

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

func TestEventStreamScriptsThenBlocksUntilClose(t *testing.T) {
	reference := harnessadapter.AttemptRef{AttemptID: "00000000-0000-4000-8000-000000000001"}
	first := harnessadapter.StartedEvent{EventBase: harnessadapter.EventBase{Attempt: reference}}
	stream := newEventStream([]harnessadapter.Event{first}, nil, false, nil)
	if got, err := stream.Next(context.Background()); err != nil || got != first {
		t.Fatalf("scripted event=%#v err=%v", got, err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := stream.Next(context.Background())
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("stream did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("close error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Next")
	}
}

func TestEventStreamHasExplicitEOFAndError(t *testing.T) {
	for name, stream := range map[string]struct {
		stream *eventStream
		want   error
	}{
		"eof":   {stream: newEventStream(nil, nil, true, nil), want: io.EOF},
		"error": {stream: newEventStream(nil, nil, false, ErrInjected), want: ErrInjected},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := stream.stream.Next(context.Background())
			if !errors.Is(err, stream.want) {
				t.Fatalf("error=%v want=%v", err, stream.want)
			}
		})
	}
}
