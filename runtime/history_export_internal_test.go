package node

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/boxvtk621/harness-codex/internal/historyreplica"
)

func TestEncodeHistoryExportPageHonorsByteBudget(t *testing.T) {
	identity := historyreplica.StreamIdentity{
		OwnerID: "1-1", LogicalDialogID: "10000000-0000-4000-8000-000000000501",
		NodeID: "10000000-0000-4000-8000-000000000502", NodeDialogID: "10000000-0000-4000-8000-000000000503",
		BindingGeneration: 1,
	}
	streamID := historyreplica.StreamID(identity)
	previous := historyreplica.ChainGenesis(streamID)
	coverage := historyreplica.GenesisHash
	records := make([]historyreplica.Record, 0, 10)
	for index := 0; index < 10; index++ {
		entity := historyreplica.StableUUID("byte-budget-entity", string(rune('a'+index)))
		record, err := historyreplica.NewRecord(historyreplica.RecordAssetManifest,
			historyreplica.StableUUID("byte-budget-record", entity), entity, 1,
			map[string]any{"blob": strings.Repeat("x", historyreplica.MaximumChunkBytes)})
		if err != nil {
			t.Fatal(err)
		}
		record, err = historyreplica.SealRecord(record, streamID, int64(index+1), previous)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
		previous = record.ChainHash
		coverage = historyreplica.FoldCoverageHash(coverage, record.RecordHash)
	}
	page := historyreplica.ExportPage{
		SchemaID: historyreplica.SchemaID, SchemaSHA256: historyreplica.SchemaSHA256,
		StreamID: streamID, Identity: identity,
		Checkpoint: historyreplica.Checkpoint{
			ThroughSeq: int64(len(records)), ChainHash: previous, DialogVersion: 1, QueueRevision: 1,
			EntriesHash: historyreplica.GenesisHash, FactsHash: historyreplica.GenesisHash,
			ReceiptsHash: historyreplica.GenesisHash, TextHash: historyreplica.GenesisHash,
			AssetManifestHash: coverage,
			EffectsSummary:    historyreplica.EffectsSummary{AssetManifestCount: int64(len(records))},
			Ready:             true, CapturedAt: "2026-09-17T00:00:00Z",
		},
	}
	trimmed, body, err := encodeHistoryExportPage(page, records)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > historyreplica.MaximumPageBytes || len(trimmed.Records) == 0 || len(trimmed.Records) >= len(records) ||
		trimmed.NextAfter == nil || *trimmed.NextAfter != trimmed.Records[len(trimmed.Records)-1].StreamSeq {
		t.Fatalf("byte-bounded page invalid: bytes=%d records=%d next=%v", len(body), len(trimmed.Records), trimmed.NextAfter)
	}
	var decoded historyreplica.ExportPage
	if json.Unmarshal(body, &decoded) != nil || historyreplica.ValidatePage(decoded) != nil {
		t.Fatal("byte-bounded page did not round-trip")
	}
}
