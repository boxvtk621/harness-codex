package node

import (
	"testing"

	"github.com/boxvtk621/harness-codex/internal/transcriptview"
)

func TestSafeTextAggregateLimit(t *testing.T) {
	tests := []struct {
		name     string
		captured int64
		size     int64
		want     bool
	}{
		{name: "exact aggregate limit", captured: transcriptview.MaximumTextBytes - 1, size: 1, want: true},
		{name: "above aggregate limit", captured: transcriptview.MaximumTextBytes, size: 1},
		{name: "single source above limit", size: transcriptview.MaximumTextBytes + 1},
		{name: "storage reserve is retained", captured: 1, size: 1, want: false},
		{name: "invalid negative accounting", captured: -1, size: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			usage := safeTextUsage{textBytes: test.captured}
			if test.name == "storage reserve is retained" {
				usage.storageBytes = safeTextMaximumStorage - safeTextLimitMarkerReserve
			}
			if got := safeTextCanStoreComplete(usage, test.size, test.size, 0); got != test.want {
				t.Fatalf("safeTextCanStoreComplete(%d,%d)=%v want=%v", test.captured, test.size, got, test.want)
			}
		})
	}
}

func TestSafeTextUsageBoundsAndEncoding(t *testing.T) {
	for _, usage := range []safeTextUsage{
		{sourceCount: safeTextMaximumSources - 1},
		{chunkCount: safeTextMaximumChunks},
		{sealed: true, sourceCount: 1},
	} {
		if safeTextCanStoreComplete(usage, 1, 1, 1) {
			t.Fatalf("bounded usage accepted another source: %+v", usage)
		}
	}
	want := safeTextUsage{textBytes: 7, storageBytes: 11, sourceCount: 2, chunkCount: 3, sealed: true}
	got, err := decodeSafeTextUsage(encodeSafeTextUsage(want), true)
	if err != nil || got != want {
		t.Fatalf("usage encoding did not round trip: got=%+v err=%v", got, err)
	}
	for _, encoded := range []string{"", "v2:7:11:2:3", "v1:07:11:2:3", "v1:7:11:2", "v1:-1:11:2:3"} {
		if _, err := decodeSafeTextUsage(encoded, false); err == nil {
			t.Fatalf("invalid usage encoding was accepted: %q", encoded)
		}
	}
}
