// Package tooltimeline owns the additive public tool-timeline-v1 read contract.
package tooltimeline

import (
	"encoding/json"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

const (
	SchemaID = "tool-timeline-v1"
	PageType = "tool_calls"
)

type Summary struct {
	ToolCallID    string `json:"toolCallId"`
	ToolName      string `json:"toolName"`
	State         string `json:"state"`
	StartedAt     string `json:"startedAt"`
	FinishedAt    string `json:"finishedAt,omitempty"`
	DetailVersion int64  `json:"detailVersion"`
}

type Page struct {
	ProtocolVersion      int       `json:"protocolVersion"`
	SchemaID             string    `json:"schemaId"`
	NodeID               string    `json:"nodeId"`
	Epoch                int64     `json:"epoch"`
	SnapshotStateVersion int64     `json:"snapshotStateVersion"`
	LastEventSeq         int64     `json:"lastEventSeq"`
	DialogID             string    `json:"dialogId"`
	RequestID            string    `json:"requestId"`
	AttemptID            string    `json:"attemptId"`
	Items                []Summary `json:"items"`
	NextCursor           *string   `json:"nextCursor"`
	PageType             string    `json:"pageType"`
}

type Output struct {
	Index      int64                       `json:"index"`
	Stream     string                      `json:"stream"`
	Content    harnessprotocol.SafeContent `json:"content"`
	ObservedAt string                      `json:"observedAt"`
}

type Detail struct {
	Summary
	Input            harnessprotocol.SafeContent  `json:"input"`
	Result           *harnessprotocol.SafeContent `json:"result,omitempty"`
	Outputs          []Output                     `json:"outputs"`
	NextOutputCursor *string                      `json:"nextOutputCursor"`
}

type DetailRead struct {
	ProtocolVersion int    `json:"protocolVersion"`
	SchemaID        string `json:"schemaId"`
	NodeID          string `json:"nodeId"`
	Epoch           int64  `json:"epoch"`
	StateVersion    int64  `json:"stateVersion"`
	LastEventSeq    int64  `json:"lastEventSeq"`
	DialogID        string `json:"dialogId"`
	RequestID       string `json:"requestId"`
	AttemptID       string `json:"attemptId"`
	ToolCall        Detail `json:"toolCall"`
}

func Marshal(value any) ([]byte, error) { return json.Marshal(value) }
