package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
)

const (
	maximumRPCIDBytes     = 512
	codexAppServerVersion = harnessadapter.CodexAppServerVersion
	codexClientName       = "homelab-harness"
	codexClientTitle      = "HomeLab Harness"
	codexClientVersion    = "1"
)

type initializeClientInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"`
}

type initializeParams struct {
	ClientInfo   initializeClientInfo   `json:"clientInfo"`
	Capabilities initializeCapabilities `json:"capabilities"`
}

type initializeCapabilities struct {
	ExperimentalAPI bool `json:"experimentalApi"`
}

type initializeResponse struct {
	UserAgent      string `json:"userAgent"`
	CodexHome      string `json:"codexHome"`
	PlatformFamily string `json:"platformFamily"`
	PlatformOS     string `json:"platformOs"`
}

type rpcError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type rpcFrame struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcID struct {
	raw json.RawMessage
	key string
}

func parseRPCID(raw json.RawMessage) (rpcID, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maximumRPCIDBytes {
		return rpcID{}, errors.New("codex app-server request ID is invalid")
	}
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil || value == "" || !utf8.ValidString(value) || len(value) > maximumRPCIDBytes {
			return rpcID{}, errors.New("codex app-server request ID is invalid")
		}
		return rpcID{raw: bytes.Clone(trimmed), key: "s:" + value}, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return rpcID{}, errors.New("codex app-server request ID is invalid")
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return rpcID{}, errors.New("codex app-server request ID is invalid")
	}
	canonical := strconv.FormatInt(value, 10)
	return rpcID{raw: json.RawMessage(canonical), key: "n:" + canonical}, nil
}

type rpcNotification struct {
	Method string
	Params json.RawMessage
}

type rpcServerRequest struct {
	ID     rpcID
	Method string
	Params json.RawMessage
}

type rpcRemoteError struct {
	code int64
}

func (err rpcRemoteError) Error() string {
	return "codex app-server rejected request with code " + strconv.FormatInt(err.code, 10)
}
