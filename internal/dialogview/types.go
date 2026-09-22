// Package dialogview owns the additive public dialog-view-v1 read contract.
package dialogview

import "encoding/json"

const (
	SchemaID = "dialog-view-v1"
	PageType = "dialogs"
)

type Dialog struct {
	DialogID        string `json:"dialogId"`
	Version         int64  `json:"version"`
	Title           string `json:"title,omitempty"`
	CreatedAt       string `json:"createdAt"`
	LastActivityAt  string `json:"lastActivityAt"`
	State           string `json:"state"`
	ActiveRequestID string `json:"activeRequestId,omitempty"`
	ActiveAttemptID string `json:"activeAttemptId,omitempty"`
}

type Page struct {
	ProtocolVersion      int      `json:"protocolVersion"`
	SchemaID             string   `json:"schemaId"`
	NodeID               string   `json:"nodeId"`
	Epoch                int64    `json:"epoch"`
	SnapshotStateVersion int64    `json:"snapshotStateVersion"`
	LastEventSeq         int64    `json:"lastEventSeq"`
	Items                []Dialog `json:"items"`
	NextCursor           *string  `json:"nextCursor"`
	PageType             string   `json:"pageType"`
}

type Read struct {
	ProtocolVersion int    `json:"protocolVersion"`
	SchemaID        string `json:"schemaId"`
	NodeID          string `json:"nodeId"`
	Epoch           int64  `json:"epoch"`
	StateVersion    int64  `json:"stateVersion"`
	LastEventSeq    int64  `json:"lastEventSeq"`
	Dialog          Dialog `json:"dialog"`
}

func Marshal(value any) ([]byte, error) { return json.Marshal(value) }
