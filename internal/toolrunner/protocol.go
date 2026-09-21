package toolrunner

import "time"

const helperProtocolVersion = 1

type helperCommand struct {
	Command       string `json:"command"`
	CWD           string `json:"cwd"`
	Access        Access `json:"access"`
	TimeoutMillis int64  `json:"timeoutMillis"`
}

type wireRequest struct {
	CallID     string             `json:"callId"`
	Workspace  string             `json:"workspace"`
	Kind       Kind               `json:"kind"`
	Command    *helperCommand     `json:"command,omitempty"`
	FileChange *FileChangeRequest `json:"fileChange,omitempty"`
}

type helperEnvelope struct {
	ProtocolVersion int         `json:"protocolVersion"`
	Mode            string      `json:"mode"`
	Request         wireRequest `json:"request"`
	SystemReadRoots []string    `json:"systemReadRoots"`
	MaximumOutput   int         `json:"maximumOutput"`
}

type helperResponse struct {
	ProtocolVersion int                `json:"protocolVersion"`
	Success         bool               `json:"success"`
	Output          []byte             `json:"output"`
	Truncated       bool               `json:"truncated"`
	ExitCode        *int               `json:"exitCode,omitempty"`
	Changes         []FileChangeResult `json:"changes,omitempty"`
	Failure         string             `json:"failure,omitempty"`
}

func toWireRequest(request Request) wireRequest {
	result := wireRequest{CallID: request.CallID, Workspace: request.Workspace, Kind: request.Kind, FileChange: request.FileChange}
	if request.Command != nil {
		result.Command = &helperCommand{Command: request.Command.Command, CWD: request.Command.CWD, Access: request.Command.Access, TimeoutMillis: request.Command.Timeout.Milliseconds()}
	}
	return result
}

func fromWireRequest(request wireRequest) Request {
	result := Request{CallID: request.CallID, Workspace: request.Workspace, Kind: request.Kind, FileChange: request.FileChange}
	if request.Command != nil {
		result.Command = &CommandRequest{Command: request.Command.Command, CWD: request.Command.CWD, Access: request.Command.Access, Timeout: time.Duration(request.Command.TimeoutMillis) * time.Millisecond}
	}
	return result
}
