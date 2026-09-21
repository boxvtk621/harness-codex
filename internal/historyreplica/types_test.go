package historyreplica

import (
	"encoding/json"
	"testing"
)

func fixtureIdentity() StreamIdentity {
	return StreamIdentity{
		OwnerID: "1-1", LogicalDialogID: "10000000-0000-4000-8000-000000000001",
		NodeID: "10000000-0000-4000-8000-000000000002", NodeDialogID: "10000000-0000-4000-8000-000000000003",
		BindingGeneration: 7,
	}
}

func TestStableStreamAndRecordChain(t *testing.T) {
	identity := fixtureIdentity()
	if StreamID(identity) != StreamID(identity) {
		t.Fatal("stream identity is not stable")
	}
	record, err := NewRecord(RecordExecutionFact,
		StableUUID("record", "1"), StableUUID("fact", "1"), 1,
		ExecutionFact{FactID: StableUUID("fact", "1"), Origin: Origin{NodeID: identity.NodeID, NodeDialogID: identity.NodeDialogID, AuthorEventID: "event:1"}, LogicalDialogID: identity.LogicalDialogID, Kind: "accepted", Status: "accepted", EventSeq: 1, OccurredAt: "2026-09-17T00:00:00Z", Event: json.RawMessage(`{"type":"message.accepted"}`)},
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err = SealRecord(record, StreamID(identity), 1, ChainGenesis(StreamID(identity)))
	if err != nil {
		t.Fatal(err)
	}
	page := ExportPage{
		SchemaID: SchemaID, SchemaSHA256: SchemaSHA256, StreamID: StreamID(identity), Identity: identity, Records: []Record{record},
		Checkpoint: Checkpoint{ThroughSeq: 1, ChainHash: record.ChainHash, DialogVersion: 1, QueueRevision: 1,
			EntriesHash: GenesisHash, FactsHash: record.RecordHash, ReceiptsHash: GenesisHash, TextHash: GenesisHash,
			AssetManifestHash: GenesisHash, EffectsSummary: EffectsSummary{FactCount: 1},
			Ready: true, CapturedAt: "2026-09-17T00:00:00Z"},
	}
	if err := ValidatePage(page); err != nil {
		t.Fatal(err)
	}
	relabeled := page
	relabeled.Identity.BindingGeneration++
	relabeled.StreamID = StreamID(relabeled.Identity)
	if err := ValidatePage(relabeled); err == nil {
		t.Fatal("chain replay under a different stream identity was accepted")
	}
	page.Records[0].Payload = json.RawMessage(`{"type":"changed"}`)
	if err := ValidatePage(page); err == nil {
		t.Fatal("payload corruption was accepted")
	}
}

func TestStreamGenerationSeparatesReturnBinding(t *testing.T) {
	first := fixtureIdentity()
	returned := first
	returned.BindingGeneration++
	if StreamID(first) == StreamID(returned) {
		t.Fatal("A to B to A return reused stream identity")
	}
	entry := StableUUID("entry", first.NodeID+"\x00message")
	if entry != StableUUID("entry", returned.NodeID+"\x00message") {
		t.Fatal("stable entry id changed with stream generation")
	}
}

func TestChunkLimitIsOneMiB(t *testing.T) {
	if MaximumChunkBytes != 1<<20 {
		t.Fatalf("unexpected chunk limit %d", MaximumChunkBytes)
	}
}
