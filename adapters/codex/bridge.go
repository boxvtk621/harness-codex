package codex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

var (
	errBridgeClosed        = errors.New("codex app-server is unavailable")
	errAcknowledgementLost = errors.New("codex app-server acknowledgement is unknown")
)

type bridgeConfig struct {
	Executable       string
	Arguments        []string
	VersionArguments []string
	Environment      []string
	WorkingDir       string
	MaxFrameBytes    int
}

type rpcResponse struct {
	result json.RawMessage
	err    error
}

type bridge struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	maximum   int
	onNotice  func(rpcNotification)
	onRequest func(rpcServerRequest)
	onExit    func()

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan rpcResponse
	inbound map[string]rpcID
	done    chan struct{}
	wait    chan error
	stopOne sync.Once
	nextID  atomic.Int64
	stopErr error
	stderr  *byteCounter
}

type byteCounter struct{ total atomic.Uint64 }

func (counter *byteCounter) Write(value []byte) (int, error) {
	counter.total.Add(uint64(len(value)))
	return len(value), nil
}

func startBridge(config bridgeConfig, onNotice func(rpcNotification), onRequest func(rpcServerRequest), onExit func()) (*bridge, error) {
	if config.Executable == "" || strings.ContainsAny(config.Executable, "\x00\r\n") || config.MaxFrameBytes < 4096 || config.MaxFrameBytes > harnessprotocol.MaximumWireBytes {
		return nil, errors.New("codex app-server bridge config is invalid")
	}
	command := exec.Command(config.Executable, config.Arguments...)
	command.Env = append([]string(nil), config.Environment...)
	command.Dir = config.WorkingDir
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &byteCounter{}
	command.Stderr = stderr
	instance := &bridge{
		cmd: command, stdin: stdin, maximum: config.MaxFrameBytes,
		onNotice: onNotice, onRequest: onRequest, onExit: onExit,
		pending: make(map[string]chan rpcResponse), inbound: make(map[string]rpcID),
		done: make(chan struct{}), wait: make(chan error, 1), stderr: stderr,
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start codex app-server: %w", err)
	}
	go func() {
		readErr := instance.read(stdout)
		if readErr != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		waitErr := command.Wait()
		if readErr == nil {
			readErr = errBridgeClosed
		}
		instance.shutdown(readErr)
		instance.wait <- waitErr
		close(instance.wait)
	}()
	return instance, nil
}

func (bridge *bridge) suppressedStderrBytes() uint64 {
	if bridge == nil || bridge.stderr == nil {
		return 0
	}
	return bridge.stderr.total.Load()
}

func (bridge *bridge) call(ctx context.Context, method string, params any, result any) error {
	return bridge.callAfterWrite(ctx, method, params, result, nil)
}

// callAfterWrite runs afterWrite after the complete request frame is written
// while writeMu is still held. A dynamic-tool response therefore cannot pass
// the interrupt frame before its execution context is canceled.
func (bridge *bridge) callAfterWrite(ctx context.Context, method string, params any, result any, afterWrite func()) error {
	if !validRPCMethod(method) {
		return errors.New("codex app-server method is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	idValue := bridge.nextID.Add(1)
	if idValue <= 0 {
		return errors.New("codex app-server request ID is exhausted")
	}
	id, err := parseRPCID(json.RawMessage(fmt.Sprintf("%d", idValue)))
	if err != nil {
		return err
	}
	request := struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params any             `json:"params"`
	}{ID: id.raw, Method: method, Params: params}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	response := make(chan rpcResponse, 1)
	bridge.mu.Lock()
	if bridge.isDoneLocked() {
		failure := bridge.failureLocked()
		bridge.mu.Unlock()
		return failure
	}
	bridge.pending[id.key] = response
	bridge.mu.Unlock()
	if err := bridge.writeAfter(encoded, afterWrite); err != nil {
		bridge.removePending(id.key)
		return errAcknowledgementLost
	}
	select {
	case reply := <-response:
		if reply.err != nil {
			return reply.err
		}
		if result != nil {
			if len(reply.result) == 0 || json.Unmarshal(reply.result, result) != nil {
				return errors.New("codex app-server response is invalid")
			}
		}
		return nil
	case <-ctx.Done():
		bridge.removePending(id.key)
		return ctx.Err()
	case <-bridge.done:
		bridge.removePending(id.key)
		bridge.mu.Lock()
		failure := bridge.failureLocked()
		bridge.mu.Unlock()
		return failure
	}
}

func (bridge *bridge) notify(method string, params any) error {
	if !validRPCMethod(method) {
		return errors.New("codex app-server method is invalid")
	}
	encoded, err := json.Marshal(struct {
		Method string `json:"method"`
		Params any    `json:"params"`
	}{Method: method, Params: params})
	if err != nil {
		return err
	}
	return bridge.write(encoded)
}

// respond consumes one exact server-request ID before writing. A failed write
// is intentionally not retryable because app-server may already have accepted
// the response.
func (bridge *bridge) respond(id rpcID, result any) error {
	encoded, err := json.Marshal(struct {
		ID     json.RawMessage `json:"id"`
		Result any             `json:"result"`
	}{ID: id.raw, Result: result})
	if err != nil {
		return err
	}
	bridge.mu.Lock()
	stored, ok := bridge.inbound[id.key]
	if ok {
		delete(bridge.inbound, id.key)
	}
	bridge.mu.Unlock()
	if !ok || !bytes.Equal(stored.raw, id.raw) {
		return errors.New("codex app-server request is not pending")
	}
	if err := bridge.write(encoded); err != nil {
		return errAcknowledgementLost
	}
	return nil
}

func (bridge *bridge) reject(id rpcID, code int64) error {
	encoded, err := json.Marshal(struct {
		ID    json.RawMessage `json:"id"`
		Error rpcError        `json:"error"`
	}{ID: id.raw, Error: rpcError{Code: code, Message: "request unsupported by harness policy"}})
	if err != nil {
		return err
	}
	bridge.mu.Lock()
	stored, ok := bridge.inbound[id.key]
	if ok {
		delete(bridge.inbound, id.key)
	}
	bridge.mu.Unlock()
	if !ok || !bytes.Equal(stored.raw, id.raw) {
		return errors.New("codex app-server request is not pending")
	}
	if err := bridge.write(encoded); err != nil {
		return errAcknowledgementLost
	}
	return nil
}

// resolveInbound forgets a native request that app-server resolved without a
// client response. The exact request ID is still compared to prevent an
// unrelated notification from clearing a pending request.
func (bridge *bridge) resolveInbound(id rpcID) bool {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	stored, ok := bridge.inbound[id.key]
	if !ok || !bytes.Equal(stored.raw, id.raw) {
		return false
	}
	delete(bridge.inbound, id.key)
	return true
}

func (bridge *bridge) write(encoded []byte) error {
	return bridge.writeAfter(encoded, nil)
}

func (bridge *bridge) writeAfter(encoded []byte, afterWrite func()) error {
	if len(encoded) == 0 || len(encoded) > bridge.maximum || bytes.IndexByte(encoded, '\n') >= 0 {
		return errors.New("codex app-server frame is invalid")
	}
	bridge.mu.Lock()
	if bridge.isDoneLocked() {
		failure := bridge.failureLocked()
		bridge.mu.Unlock()
		return failure
	}
	bridge.mu.Unlock()
	bridge.writeMu.Lock()
	_, err := bridge.stdin.Write(append(encoded, '\n'))
	if afterWrite != nil {
		afterWrite()
	}
	bridge.writeMu.Unlock()
	if err != nil {
		return errAcknowledgementLost
	}
	return nil
}

func (bridge *bridge) read(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), bridge.maximum)
	for scanner.Scan() {
		if err := bridge.route(scanner.Bytes()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("codex app-server frame exceeds limit")
	}
	return nil
}

func (bridge *bridge) route(encoded []byte) error {
	var frame rpcFrame
	if len(encoded) == 0 || len(encoded) > bridge.maximum || json.Unmarshal(encoded, &frame) != nil {
		return errors.New("codex app-server emitted an invalid frame")
	}
	if frame.JSONRPC != "" && frame.JSONRPC != "2.0" {
		return errors.New("codex app-server emitted an invalid protocol version")
	}
	if frame.Method != "" {
		if !validRPCMethod(frame.Method) || frame.Result != nil || frame.Error != nil {
			return errors.New("codex app-server emitted an invalid request")
		}
		if len(frame.ID) == 0 {
			if bridge.onNotice != nil {
				bridge.onNotice(rpcNotification{Method: frame.Method, Params: bytes.Clone(frame.Params)})
			}
			return nil
		}
		id, err := parseRPCID(frame.ID)
		if err != nil {
			return err
		}
		bridge.mu.Lock()
		if _, duplicate := bridge.inbound[id.key]; duplicate {
			bridge.mu.Unlock()
			return errors.New("codex app-server repeated a pending request ID")
		}
		bridge.inbound[id.key] = id
		bridge.mu.Unlock()
		request := rpcServerRequest{ID: id, Method: frame.Method, Params: bytes.Clone(frame.Params)}
		if bridge.onRequest != nil {
			bridge.onRequest(request)
			return nil
		}
		return bridge.reject(id, -32601)
	}
	if len(frame.ID) == 0 || (frame.Result != nil) == (frame.Error != nil) {
		return errors.New("codex app-server emitted an invalid response")
	}
	id, err := parseRPCID(frame.ID)
	if err != nil {
		return err
	}
	bridge.mu.Lock()
	pending := bridge.pending[id.key]
	delete(bridge.pending, id.key)
	bridge.mu.Unlock()
	if pending == nil {
		return nil
	}
	if frame.Error != nil {
		pending <- rpcResponse{err: rpcRemoteError{code: frame.Error.Code}}
	} else {
		pending <- rpcResponse{result: bytes.Clone(frame.Result)}
	}
	return nil
}

func (bridge *bridge) removePending(key string) {
	bridge.mu.Lock()
	delete(bridge.pending, key)
	bridge.mu.Unlock()
}

func (bridge *bridge) shutdown(err error) {
	bridge.stopOne.Do(func() {
		bridge.mu.Lock()
		bridge.stopErr = err
		close(bridge.done)
		pending := bridge.pending
		bridge.pending = make(map[string]chan rpcResponse)
		bridge.inbound = make(map[string]rpcID)
		bridge.mu.Unlock()
		_ = bridge.stdin.Close()
		for _, response := range pending {
			response <- rpcResponse{err: err}
		}
		if bridge.onExit != nil {
			bridge.onExit()
		}
	})
}

func (bridge *bridge) isDoneLocked() bool {
	select {
	case <-bridge.done:
		return true
	default:
		return false
	}
}

func (bridge *bridge) failureLocked() error {
	if bridge.stopErr != nil {
		return bridge.stopErr
	}
	return errBridgeClosed
}

func (bridge *bridge) Close() error {
	bridge.stop()
	return <-bridge.wait
}

// stop is safe from callbacks running on the bridge read goroutine: it never
// waits for that goroutine to reach Cmd.Wait.
func (bridge *bridge) stop() {
	bridge.shutdown(errBridgeClosed)
	if bridge.cmd.Process != nil {
		_ = bridge.cmd.Process.Kill()
	}
}

func validRPCMethod(method string) bool {
	return method != "" && len(method) <= 256 && utf8.ValidString(method) && !strings.ContainsAny(method, "\x00\r\n")
}
