package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/toolrunner"
)

type nativeDynamicContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type nativeDynamicToolResponse struct {
	ContentItems []nativeDynamicContentItem `json:"contentItems"`
	Success      bool                       `json:"success"`
}

type nativeItem struct {
	ID           string                     `json:"id"`
	Type         string                     `json:"type"`
	Text         string                     `json:"text"`
	Status       string                     `json:"status"`
	Server       string                     `json:"server"`
	Tool         string                     `json:"tool"`
	Namespace    *string                    `json:"namespace"`
	Arguments    json.RawMessage            `json:"arguments"`
	ContentItems []nativeDynamicContentItem `json:"contentItems"`
	DurationMS   *int64                     `json:"durationMs"`
	Success      *bool                      `json:"success"`
}

type nativeItemParams struct {
	ThreadID string     `json:"threadId"`
	TurnID   string     `json:"turnId"`
	Item     nativeItem `json:"item"`
}

type nativeTurnNotice struct {
	ThreadID string `json:"threadId"`
	Turn     struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"turn"`
}

type nativeDeltaParams struct {
	ThreadID string `json:"threadId"`
	TurnID   string `json:"turnId"`
	ItemID   string `json:"itemId"`
	Delta    string `json:"delta"`
}

type nativeUsageParams struct {
	ThreadID   string `json:"threadId"`
	TurnID     string `json:"turnId"`
	TokenUsage struct {
		Last  nativeUsage `json:"last"`
		Total nativeUsage `json:"total"`
	} `json:"tokenUsage"`
}

type nativeRequestBase struct {
	ThreadID string `json:"threadId"`
	TurnID   string `json:"turnId"`
	ItemID   string `json:"itemId"`
}

type nativeDynamicToolRequest struct {
	ThreadID  string          `json:"threadId"`
	TurnID    string          `json:"turnId"`
	CallID    string          `json:"callId"`
	Namespace *string         `json:"namespace"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

type nativeInputQuestion struct {
	ID       string `json:"id"`
	Header   string `json:"header"`
	Question string `json:"question"`
	IsSecret bool   `json:"isSecret"`
}

type nativeInputRequest struct {
	nativeRequestBase
	IsBlocking bool                  `json:"isBlocking"`
	Questions  []nativeInputQuestion `json:"questions"`
}

type nativeRequestResolved struct {
	ThreadID  string          `json:"threadId"`
	RequestID json.RawMessage `json:"requestId"`
}

type nativeErrorNotice struct {
	ThreadID  string `json:"threadId"`
	TurnID    string `json:"turnId"`
	WillRetry bool   `json:"willRetry"`
	Error     struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (adapter *Adapter) handleNotification(notification rpcNotification) {
	if adapter.handleProviderAuthNotification(notification) {
		return
	}
	switch notification.Method {
	case "turn/started":
		var params nativeTurnNotice
		if json.Unmarshal(notification.Params, &params) != nil || !boundedNativeID(params.ThreadID) || !boundedNativeID(params.Turn.ID) || params.Turn.Status != "inProgress" {
			adapter.failActive("adapter_protocol")
			return
		}
		adapter.mu.Lock()
		native := adapter.byThread[params.ThreadID]
		adapter.mu.Unlock()
		if native != nil && !adapter.bindTurn(native, params.Turn.ID) {
			native.runtime.failUnknown("adapter_protocol")
		}
	case "item/agentMessage/delta":
		var params nativeDeltaParams
		if json.Unmarshal(notification.Params, &params) != nil || !boundedNativeID(params.ItemID) || !utf8.ValidString(params.Delta) {
			adapter.failActive("adapter_protocol")
			return
		}
		native := adapter.nativeFor(params.ThreadID, params.TurnID)
		if native == nil {
			return
		}
		adapter.confirmAttemptInputs(native)
		native.runtime.push(harnessadapter.AssistantDeltaEvent{
			EventBase: harnessadapter.EventBase{Attempt: native.reference},
			MessageID: derivedUUID("codex-message", params.ItemID), Content: safeInline(params.Delta),
		})
	case "item/started", "item/completed":
		var params nativeItemParams
		if json.Unmarshal(notification.Params, &params) != nil || !boundedNativeID(params.Item.ID) {
			adapter.failActive("adapter_protocol")
			return
		}
		if native := adapter.nativeFor(params.ThreadID, params.TurnID); native != nil {
			adapter.confirmAttemptInputs(native)
			adapter.handleItem(native, notification.Method, params.Item)
		}
	case "item/commandExecution/outputDelta", "item/fileChange/patchUpdated", "item/commandExecution/terminalInteraction", "item/fileChange/outputDelta":
		// Every native shell/file lifecycle is disabled. Seeing one is a policy
		// violation rather than an alternate path around dynamicTools.
		adapter.failActive("adapter_protocol")
	case "thread/tokenUsage/updated":
		var params nativeUsageParams
		if json.Unmarshal(notification.Params, &params) != nil {
			adapter.failActive("adapter_protocol")
			return
		}
		if native := adapter.nativeFor(params.ThreadID, params.TurnID); native != nil {
			adapter.confirmAttemptInputs(native)
			adapter.handleUsage(native, params.TokenUsage.Last)
		}
	case "turn/completed":
		var params nativeTurnNotice
		if json.Unmarshal(notification.Params, &params) != nil || !boundedNativeID(params.Turn.ID) {
			adapter.failActive("adapter_protocol")
			return
		}
		if native := adapter.nativeFor(params.ThreadID, params.Turn.ID); native != nil {
			adapter.finish(native, params.Turn.Status)
		}
	case "serverRequest/resolved":
		var params nativeRequestResolved
		id, err := parseResolvedRequest(notification.Params, &params)
		if err != nil {
			adapter.failActive("adapter_protocol")
			return
		}
		adapter.resolveNativeRequest(params.ThreadID, id)
	case "error":
		var params nativeErrorNotice
		if json.Unmarshal(notification.Params, &params) != nil || !boundedNativeID(params.ThreadID) || !boundedNativeID(params.TurnID) ||
			params.Error.Message == "" || len(params.Error.Message) > 64<<10 || !utf8.ValidString(params.Error.Message) {
			adapter.failActive("adapter_protocol")
			return
		}
		if native := adapter.nativeFor(params.ThreadID, params.TurnID); native != nil && !params.WillRetry {
			adapter.finish(native, "failed")
		}
	case "item/plan/delta", "item/reasoning/summaryPartAdded", "item/reasoning/summaryTextDelta", "item/reasoning/textDelta":
		// Passive display-only deltas are intentionally not projected.
	default:
		if strings.HasPrefix(notification.Method, "item/") {
			adapter.failActive("adapter_protocol")
		}
	}
}

func parseResolvedRequest(encoded json.RawMessage, params *nativeRequestResolved) (rpcID, error) {
	if json.Unmarshal(encoded, params) != nil || !boundedNativeID(params.ThreadID) {
		return rpcID{}, errors.New("codex resolved request is invalid")
	}
	return parseRPCID(params.RequestID)
}

func (adapter *Adapter) handleRequest(request rpcServerRequest) {
	switch request.Method {
	case "item/tool/call":
		adapter.handleDynamicToolRequest(request)
	case "item/commandExecution/requestApproval", "item/fileChange/requestApproval":
		// Native execution stays disabled even in explicit_once mode.
		var params nativeRequestBase
		if json.Unmarshal(request.Params, &params) != nil || adapter.nativeFor(params.ThreadID, params.TurnID) == nil {
			adapter.rejectNativeRequest(request.ID, nil)
			return
		}
		native := adapter.nativeFor(params.ThreadID, params.TurnID)
		if err := adapter.session.Respond(request.ID, map[string]string{"decision": "decline"}); err != nil {
			native.runtime.failUnknown("provider_state")
		}
		native.runtime.failUnknown("adapter_protocol")
	case "item/tool/requestUserInput":
		adapter.handleInputRequest(request)
	default:
		if err := adapter.session.Reject(request.ID, -32601); err != nil {
			adapter.failActive("provider_state")
		}
	}
}

func (adapter *Adapter) handleDynamicToolRequest(request rpcServerRequest) {
	var params nativeDynamicToolRequest
	if !decodeStrict(request.Params, &params) || params.Namespace == nil || *params.Namespace != "codex" ||
		!boundedNativeID(params.CallID) || (params.Tool != "command" && params.Tool != "file_change") || len(params.Arguments) == 0 {
		adapter.rejectNativeRequest(request.ID, nil)
		return
	}
	native := adapter.nativeFor(params.ThreadID, params.TurnID)
	if native == nil {
		adapter.rejectNativeRequest(request.ID, nil)
		return
	}
	if native.policy != harnessadapter.ApprovalModeExplicitOnce || adapter.config.Runner == nil {
		_ = adapter.session.Respond(request.ID, declinedDynamicResponse())
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	tool, ok, startedByRequest := native.admitDynamicToolRequest(params)
	if !ok {
		native.cancelTools()
		if tool.requested {
			_ = adapter.session.Respond(tool.requestID, failedDynamicResponse())
		}
		_ = adapter.session.Respond(request.ID, declinedDynamicResponse())
		adapter.resolveAttemptApprovals(native, false)
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	if startedByRequest {
		native.runtime.push(harnessadapter.ToolStartedEvent{
			EventBase: harnessadapter.EventBase{Attempt: native.reference},
			CallID:    tool.callID, ToolName: tool.toolName, ActionHash: tool.actionHash, Input: tool.input,
		})
	}
	tool, claimed := native.claimToolRequest(tool.itemID, tool.actionHash, request.ID)
	if !claimed {
		// A new RPC ID for one provider item must never create another approval
		// or execution. Cancel the sole claimed call and fail the attempt closed.
		native.cancelTools()
		response := failedDynamicResponse()
		priorErr := adapter.session.Respond(tool.requestID, response)
		currentErr := adapter.session.Respond(request.ID, response)
		adapter.resolveAttemptApprovals(native, false)
		if priorErr != nil || currentErr != nil {
			native.runtime.failUnknown("provider_state")
			return
		}
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	if tool.request.Command != nil && tool.request.Command.Access == toolrunner.AccessRead {
		if !adapter.reserveToolCall(native) {
			response := failedDynamicResponse()
			if !adapter.setExpectedToolResponse(native, tool.itemID, response, "none", false, nil, false) || adapter.session.Respond(request.ID, response) != nil {
				native.runtime.failUnknown("provider_state")
			}
			return
		}
		go adapter.runReadDynamicTool(request.ID, native, tool)
		return
	}
	adapter.registerApproval(request.ID, native, tool, tool.safePrompt)
}

func (native *nativeAttempt) admitDynamicToolRequest(params nativeDynamicToolRequest) (nativeTool, bool, bool) {
	// Code Mode delegates a dynamic tool through item/tool/call before it emits
	// item/started (and may omit that notification). Treat the strictly decoded
	// request as the lifecycle start while retaining the same runner boundary.
	item := nativeItem{
		ID: params.CallID, Type: "dynamicToolCall", Status: "inProgress",
		Namespace: params.Namespace, Tool: params.Tool, Arguments: params.Arguments,
	}
	prepared, ok := prepareDynamicTool(native, item)
	if !ok {
		return nativeTool{}, false, false
	}
	native.mu.Lock()
	defer native.mu.Unlock()
	existing, exists := native.tools[item.ID]
	if exists {
		valid := existing.started && !existing.done && existing.callID == prepared.callID && existing.toolName == prepared.toolName &&
			existing.actionHash == prepared.actionHash && bytes.Equal(existing.canonicalArgs, prepared.canonicalArgs)
		return existing, valid, false
	}
	prepared.startedByRequest = true
	native.tools[item.ID] = prepared
	return prepared, true, true
}

func (adapter *Adapter) runReadDynamicTool(id rpcID, native *nativeAttempt, tool nativeTool) {
	defer adapter.releaseToolCall(native)
	result, runErr := adapter.config.Runner.Run(native.toolCtx, tool.request)
	response := safeRunnerResponse(result, runErr)
	fullSafeOutput, fullIncomplete := safeRunnerFullText(result, runErr)
	if !adapter.setExpectedToolResponse(native, tool.itemID, response, "none", result.Truncated, fullSafeOutput, fullIncomplete) {
		_ = adapter.session.Respond(id, failedDynamicResponse())
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	if err := adapter.session.Respond(id, response); err != nil {
		native.runtime.failUnknown("provider_state")
	}
}

func (adapter *Adapter) reserveToolCall(native *nativeAttempt) bool {
	native.mu.Lock()
	if native.toolCalls >= maximumToolCallsAttempt {
		native.mu.Unlock()
		return false
	}
	select {
	case adapter.toolCallSlots <- struct{}{}:
		native.toolCalls++
		native.mu.Unlock()
		return true
	default:
		native.mu.Unlock()
		return false
	}
}

func (adapter *Adapter) releaseToolCall(native *nativeAttempt) {
	native.mu.Lock()
	if native.toolCalls > 0 {
		native.toolCalls--
		<-adapter.toolCallSlots
	}
	native.mu.Unlock()
}

func (adapter *Adapter) handleInputRequest(request rpcServerRequest) {
	var params nativeInputRequest
	if json.Unmarshal(request.Params, &params) != nil || !params.IsBlocking || len(params.Questions) != 1 {
		adapter.rejectNativeRequest(request.ID, nil)
		return
	}
	native := adapter.nativeFor(params.ThreadID, params.TurnID)
	question := params.Questions[0]
	if native == nil || question.IsSecret || !boundedQuestion(question.ID) || !boundedText(question.Question) {
		adapter.rejectNativeRequest(request.ID, native)
		return
	}
	inputID := derivedUUID("codex-input", attemptKey(native.reference)+"\x00"+request.ID.key)
	adapter.mu.Lock()
	_, duplicateID := adapter.inputs[inputID]
	_, duplicateRPC := adapter.inputByRPC[request.ID.key]
	admitted := !duplicateID && !duplicateRPC && adapter.hasInteractionCapacityLocked(native)
	if admitted {
		adapter.inputs[inputID] = &pendingInput{id: request.ID, attempt: native, questionID: question.ID, result: make(chan bool, 1)}
		adapter.inputByRPC[request.ID.key] = inputID
	}
	adapter.mu.Unlock()
	if duplicateID || duplicateRPC {
		adapter.rejectNativeRequest(request.ID, native)
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	if !admitted {
		adapter.rejectNativeRequest(request.ID, native)
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	native.runtime.setWaitingInput(true)
	native.runtime.push(harnessadapter.InputRequestedEvent{
		EventBase: harnessadapter.EventBase{Attempt: native.reference}, InputRequestID: inputID, Prompt: safeInline(question.Question),
	})
}

func (adapter *Adapter) registerApproval(id rpcID, native *nativeAttempt, tool nativeTool, prompt string) {
	approvalID := derivedUUID("codex-approval", attemptKey(native.reference)+"\x00"+id.key)
	pending := &pendingApproval{id: id, attempt: native, itemID: tool.itemID, actionHash: tool.actionHash, result: make(chan bool, 1)}
	adapter.mu.Lock()
	_, duplicateID := adapter.approvals[approvalID]
	_, duplicateRPC := adapter.approvalByRPC[id.key]
	admitted := !duplicateID && !duplicateRPC && adapter.hasInteractionCapacityLocked(native)
	if admitted {
		adapter.approvals[approvalID] = pending
		adapter.approvalByRPC[id.key] = approvalID
	}
	adapter.mu.Unlock()
	if duplicateID || duplicateRPC {
		adapter.rejectNativeRequest(id, native)
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	if !admitted {
		response := failedDynamicResponse()
		if !adapter.setExpectedToolResponse(native, tool.itemID, response, "none", false, nil, false) {
			adapter.rejectNativeRequest(id, native)
			native.runtime.failUnknown("adapter_protocol")
			return
		}
		if err := adapter.session.Respond(id, response); err != nil {
			native.runtime.failUnknown("provider_state")
		}
		return
	}
	native.runtime.setWaitingInput(true)
	native.runtime.push(harnessadapter.ApprovalRequestedEvent{
		EventBase: harnessadapter.EventBase{Attempt: native.reference}, ApprovalID: approvalID,
		CallID: tool.callID, ActionHash: tool.actionHash, SafePrompt: prompt,
	})
}

func (adapter *Adapter) hasInteractionCapacityLocked(native *nativeAttempt) bool {
	if len(adapter.approvals)+len(adapter.inputs) >= maximumInteractions {
		return false
	}
	count := 0
	for _, pending := range adapter.approvals {
		if pending.attempt == native {
			count++
		}
	}
	for _, pending := range adapter.inputs {
		if pending.attempt == native {
			count++
		}
	}
	return count < maximumInteractionsTurn
}

func declinedDynamicResponse() nativeDynamicToolResponse {
	return nativeDynamicToolResponse{Success: false, ContentItems: []nativeDynamicContentItem{{Type: "inputText", Text: "Действие отклонено оператором."}}}
}

func failedDynamicResponse() nativeDynamicToolResponse {
	return nativeDynamicToolResponse{Success: false, ContentItems: []nativeDynamicContentItem{{Type: "inputText", Text: "Изолированный инструмент завершился ошибкой."}}}
}

func rejectResultResponse() harnessprotocol.SafeContent {
	return redactedInline("Изолированное действие отклонено или завершилось ошибкой.")
}

func (adapter *Adapter) rejectNativeRequest(id rpcID, native *nativeAttempt) {
	if err := adapter.session.Reject(id, -32602); err != nil && native != nil {
		native.runtime.failUnknown("provider_state")
	}
}

func (adapter *Adapter) resolveNativeRequest(threadID string, id rpcID) {
	adapter.mu.Lock()
	approvalID := adapter.approvalByRPC[id.key]
	pendingApproval := adapter.approvals[approvalID]
	adapter.mu.Unlock()
	if pendingApproval != nil {
		adapter.resolveNativeApproval(threadID, id)
		return
	}
	adapter.resolveNativeInput(threadID, id)
}

func (adapter *Adapter) resolveNativeApproval(threadID string, id rpcID) {
	adapter.mu.Lock()
	approvalID := adapter.approvalByRPC[id.key]
	pending := adapter.approvals[approvalID]
	if pending == nil || pending.attempt.threadID != threadID {
		adapter.mu.Unlock()
		_ = adapter.session.ResolveInbound(id)
		return
	}
	if pending.resolved {
		adapter.mu.Unlock()
		pending.attempt.runtime.failUnknown("adapter_protocol")
		return
	}
	if pending.responding {
		pending.resolved = true
		adapter.mu.Unlock()
		_ = adapter.session.ResolveInbound(id)
		if pending.attempt.toolCompleted(pending.itemID, pending.actionHash) {
			adapter.resolvePendingApproval(approvalID, true)
		}
		return
	}
	delete(adapter.approvals, approvalID)
	delete(adapter.approvalByRPC, id.key)
	adapter.mu.Unlock()
	_ = adapter.session.ResolveInbound(id)
	pending.attempt.runtime.setWaitingInput(false)
}

func (adapter *Adapter) resolveNativeInput(threadID string, id rpcID) {
	adapter.mu.Lock()
	inputID := adapter.inputByRPC[id.key]
	pending := adapter.inputs[inputID]
	if pending == nil || pending.attempt.threadID != threadID {
		adapter.mu.Unlock()
		_ = adapter.session.ResolveInbound(id)
		return
	}
	delete(adapter.inputByRPC, id.key)
	if pending.responding {
		pending.resolved = true
		adapter.mu.Unlock()
		_ = adapter.session.ResolveInbound(id)
		return
	}
	delete(adapter.inputs, inputID)
	adapter.mu.Unlock()
	_ = adapter.session.ResolveInbound(id)
	pending.attempt.runtime.setWaitingInput(false)
	pending.result <- false
}

func (adapter *Adapter) resolvePendingInput(inputID string, applied bool) {
	adapter.mu.Lock()
	pending := adapter.inputs[inputID]
	if pending != nil {
		delete(adapter.inputs, inputID)
		delete(adapter.inputByRPC, pending.id.key)
	}
	adapter.mu.Unlock()
	if pending != nil {
		_ = adapter.session.ResolveInbound(pending.id)
		pending.attempt.runtime.setWaitingInput(false)
		pending.result <- applied
	}
}

func (adapter *Adapter) resolvePendingApproval(approvalID string, applied bool) {
	adapter.mu.Lock()
	pending := adapter.approvals[approvalID]
	if pending != nil {
		delete(adapter.approvals, approvalID)
		delete(adapter.approvalByRPC, pending.id.key)
	}
	adapter.mu.Unlock()
	if pending != nil {
		_ = adapter.session.ResolveInbound(pending.id)
		pending.attempt.runtime.setWaitingInput(false)
		pending.result <- applied
	}
}

func (adapter *Adapter) resolveAttemptApprovals(native *nativeAttempt, applied bool) bool {
	adapter.mu.Lock()
	ids := make([]string, 0)
	responseUnconfirmed := false
	for approvalID, pending := range adapter.approvals {
		if pending.attempt == native {
			ids = append(ids, approvalID)
			responseUnconfirmed = responseUnconfirmed || pending.responding
		}
	}
	adapter.mu.Unlock()
	for _, approvalID := range ids {
		adapter.resolvePendingApproval(approvalID, applied)
	}
	return responseUnconfirmed
}

func (adapter *Adapter) resolveAttemptInputs(native *nativeAttempt, applied bool) bool {
	adapter.mu.Lock()
	ids := make([]string, 0)
	responseUnconfirmed := false
	for inputID, pending := range adapter.inputs {
		if pending.attempt == native {
			ids = append(ids, inputID)
			responseUnconfirmed = responseUnconfirmed || pending.responding
		}
	}
	adapter.mu.Unlock()
	for _, inputID := range ids {
		adapter.resolvePendingInput(inputID, applied)
	}
	return responseUnconfirmed
}

func (adapter *Adapter) confirmAttemptInputs(native *nativeAttempt) {
	adapter.mu.Lock()
	ids := make([]string, 0)
	for inputID, pending := range adapter.inputs {
		if pending.attempt == native && pending.responding && pending.resolved {
			ids = append(ids, inputID)
		}
	}
	adapter.mu.Unlock()
	for _, inputID := range ids {
		adapter.resolvePendingInput(inputID, true)
	}
}

func (adapter *Adapter) confirmAttemptApprovals(native *nativeAttempt, itemID string) {
	adapter.mu.Lock()
	ids := make([]string, 0)
	for approvalID, pending := range adapter.approvals {
		if pending.attempt == native && pending.itemID == itemID && pending.responding {
			ids = append(ids, approvalID)
		}
	}
	adapter.mu.Unlock()
	for _, approvalID := range ids {
		adapter.resolvePendingApproval(approvalID, true)
	}
}

func (adapter *Adapter) nativeFor(threadID, turnID string) *nativeAttempt {
	if !boundedNativeID(threadID) || !boundedNativeID(turnID) {
		return nil
	}
	adapter.mu.Lock()
	native := adapter.byTurn[turnKey(threadID, turnID)]
	adapter.mu.Unlock()
	return native
}

func (native *nativeAttempt) tool(itemID string) (nativeTool, bool) {
	if !boundedNativeID(itemID) {
		return nativeTool{}, false
	}
	native.mu.Lock()
	defer native.mu.Unlock()
	tool, ok := native.tools[itemID]
	return tool, ok && tool.started && !tool.done && tool.callID != "" && validPolicyHash(tool.actionHash)
}

func (native *nativeAttempt) claimToolRequest(itemID, actionHash string, requestID rpcID) (nativeTool, bool) {
	native.mu.Lock()
	defer native.mu.Unlock()
	tool, ok := native.tools[itemID]
	if !ok || !tool.started || tool.done || tool.callID == "" || tool.actionHash != actionHash || !validPolicyHash(actionHash) {
		return tool, false
	}
	if tool.requested {
		return tool, false
	}
	tool.requested = true
	tool.requestID = requestID
	native.tools[itemID] = tool
	return tool, true
}

func (native *nativeAttempt) hasOpenTools() bool {
	native.mu.Lock()
	defer native.mu.Unlock()
	for _, tool := range native.tools {
		if tool.started && !tool.done {
			return true
		}
	}
	return false
}

func (native *nativeAttempt) toolCompleted(itemID, actionHash string) bool {
	native.mu.Lock()
	defer native.mu.Unlock()
	tool, ok := native.tools[itemID]
	return ok && tool.done && tool.actionHash == actionHash
}

func (adapter *Adapter) handleItem(native *nativeAttempt, method string, item nativeItem) {
	base := harnessadapter.EventBase{Attempt: native.reference}
	switch item.Type {
	case "agentMessage":
		if method != "item/completed" || !utf8.ValidString(item.Text) {
			return
		}
		content := safeInline(item.Text)
		fullText := item.Text
		native.mu.Lock()
		copyContent := content
		native.output = &copyContent
		native.mu.Unlock()
		native.runtime.push(harnessadapter.AssistantMessageEvent{
			EventBase: base, MessageID: derivedUUID("codex-message", item.ID), Content: content, FinishReason: finishReason(content), FullText: &fullText,
		})
		return
	case "userMessage", "hookPrompt", "plan", "reasoning", "contextCompaction":
		return
	case "dynamicToolCall":
		adapter.handleDynamicToolItem(native, method, item)
		return
	case "commandExecution", "fileChange", "mcpToolCall":
		native.runtime.failUnknown("adapter_protocol")
		return
	default:
		native.runtime.failUnknown("adapter_protocol")
	}
}

func (adapter *Adapter) handleDynamicToolItem(native *nativeAttempt, method string, item nativeItem) {
	if native.policy != harnessadapter.ApprovalModeExplicitOnce || item.Namespace == nil || *item.Namespace != "codex" {
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	tool, ok := prepareDynamicTool(native, item)
	if !ok {
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	base := harnessadapter.EventBase{Attempt: native.reference}
	if method == "item/started" {
		if item.Status != "inProgress" || item.Success != nil || item.DurationMS != nil || item.ContentItems != nil {
			native.runtime.failUnknown("adapter_protocol")
			return
		}
		native.mu.Lock()
		existing, duplicate := native.tools[item.ID]
		lateMatchingStart := duplicate && existing.startedByRequest && !existing.done && existing.callID == tool.callID &&
			existing.toolName == tool.toolName && existing.actionHash == tool.actionHash && bytes.Equal(existing.canonicalArgs, tool.canonicalArgs)
		if !duplicate {
			native.tools[item.ID] = tool
		} else if lateMatchingStart {
			existing.startedByRequest = false
			native.tools[item.ID] = existing
		}
		native.mu.Unlock()
		if duplicate && !lateMatchingStart {
			native.runtime.failUnknown("adapter_protocol")
			return
		}
		if lateMatchingStart {
			return
		}
		native.runtime.push(harnessadapter.ToolStartedEvent{
			EventBase: base, CallID: tool.callID, ToolName: tool.toolName, ActionHash: tool.actionHash, Input: tool.input,
		})
		return
	}
	if method != "item/completed" || (item.Status != "completed" && item.Status != "failed") || item.Success == nil || (item.DurationMS != nil && *item.DurationMS < 0) {
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	native.mu.Lock()
	state, exists := native.tools[item.ID]
	if !exists || state.done || state.expectedResponse == nil || state.actionHash != tool.actionHash || state.toolName != tool.toolName ||
		!sameDynamicResponse(*state.expectedResponse, item.ContentItems, *item.Success) {
		native.mu.Unlock()
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	state.done = true
	native.tools[item.ID] = state
	native.mu.Unlock()
	result := safeDynamicResponse(*state.expectedResponse)
	if state.fullSafeOutput != nil {
		result = safeNativeOutput(*state.fullSafeOutput, state.fullIncomplete)
	} else {
		result.Truncated = result.Truncated || state.outputTruncated
	}
	native.runtime.push(harnessadapter.ToolOutputEvent{
		EventBase: base, CallID: state.callID, ChunkIndex: 0, Stream: "result", Output: result,
		FullText: state.fullSafeOutput, FullTextIncomplete: state.fullIncomplete,
	})
	if state.outputTruncated {
		pushOutputLimit(native, state.callID, 1)
	}
	status := "failed"
	if item.Status == "completed" && *item.Success {
		status = "succeeded"
	}
	effectStatus := state.effectStatus
	if effectStatus != "none" && effectStatus != "known" && effectStatus != "unknown" {
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	effectRef := ""
	if effectStatus == "known" {
		effectRef = state.actionHash
	}
	native.runtime.push(harnessadapter.ToolCompletedEvent{
		EventBase: base, CallID: state.callID, Status: status, Result: result, EffectStatus: effectStatus, EffectRef: effectRef,
		FullText: state.fullSafeOutput, FullTextIncomplete: state.fullIncomplete,
	})
	adapter.confirmAttemptApprovals(native, item.ID)
	if effectStatus == "unknown" {
		native.runtime.failUnknown("provider_state")
	}
}

func prepareDynamicTool(native *nativeAttempt, item nativeItem) (nativeTool, bool) {
	if !boundedNativeID(item.ID) || item.Namespace == nil || *item.Namespace != "codex" || (item.Tool != "command" && item.Tool != "file_change") {
		return nativeTool{}, false
	}
	callID := derivedUUID("codex-tool", attemptKey(native.reference)+"\x00"+item.ID)
	request, canonical, input, prompt, ok := decodeDynamicArguments(item.Tool, item.Arguments, native.workspace, callID)
	if !ok {
		return nativeTool{}, false
	}
	actionHash := dynamicActionHash(native, item.ID, item.Tool, canonical)
	return nativeTool{
		itemID: item.ID, callID: callID, toolName: "codex." + item.Tool, actionHash: actionHash,
		canonicalArgs: canonical, request: request, input: input, safePrompt: prompt, started: true,
	}, validPolicyHash(actionHash)
}

type commandArguments struct {
	Command        string            `json:"command"`
	CWD            string            `json:"cwd"`
	Access         toolrunner.Access `json:"access"`
	TimeoutSeconds int64             `json:"timeoutSeconds"`
}

type fileChangeArguments struct {
	Changes []fileChangeArgument `json:"changes"`
}

type fileChangeArgument struct {
	Path           string                   `json:"path"`
	Operation      toolrunner.FileOperation `json:"operation"`
	ExpectedSHA256 json.RawMessage          `json:"expectedSha256"`
	Content        json.RawMessage          `json:"content"`
}

func decodeDynamicArguments(tool string, arguments json.RawMessage, workspace, callID string) (toolrunner.Request, []byte, harnessprotocol.SafeContent, string, bool) {
	if len(arguments) == 0 || len(arguments) > toolrunner.MaximumChangeBytes+toolrunner.MaximumCommandBytes+256<<10 {
		return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
	}
	request := toolrunner.Request{CallID: callID, Workspace: workspace}
	if tool == "command" {
		var value commandArguments
		if !decodeStrict(arguments, &value) || value.TimeoutSeconds < 1 || value.TimeoutSeconds > int64(toolrunner.MaximumRuntime/time.Second) {
			return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
		}
		request.Kind = toolrunner.KindCommand
		request.Command = &toolrunner.CommandRequest{Command: value.Command, CWD: value.CWD, Access: value.Access, Timeout: time.Duration(value.TimeoutSeconds) * time.Second}
		if toolrunner.ValidateRequest(request) != nil {
			return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
		}
		canonical, _ := json.Marshal(value)
		input, prompt := commandPreview(value)
		return request, canonical, input, prompt, true
	}
	if tool != "file_change" {
		return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
	}
	var value fileChangeArguments
	if !decodeStrict(arguments, &value) || len(value.Changes) == 0 || len(value.Changes) > toolrunner.MaximumChanges {
		return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
	}
	request.Kind = toolrunner.KindFileChange
	request.FileChange = &toolrunner.FileChangeRequest{Changes: make([]toolrunner.FileChange, 0, len(value.Changes))}
	type canonicalChange struct {
		Path           string                   `json:"path"`
		Operation      toolrunner.FileOperation `json:"operation"`
		ExpectedSHA256 *string                  `json:"expectedSha256"`
		Content        *string                  `json:"content"`
	}
	canonical := struct {
		Changes []canonicalChange `json:"changes"`
	}{Changes: make([]canonicalChange, 0, len(value.Changes))}
	for _, item := range value.Changes {
		var expected *string
		if !rawJSONNullableString(item.ExpectedSHA256, &expected) {
			return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
		}
		var content *string
		if !rawJSONNullableString(item.Content, &content) || (item.Operation == toolrunner.FileWrite && content == nil) || (item.Operation == toolrunner.FileDelete && content != nil) {
			return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
		}
		change := toolrunner.FileChange{Path: item.Path, Operation: item.Operation, ExpectedSHA256: expected}
		if content != nil {
			change.Content = []byte(*content)
		}
		request.FileChange.Changes = append(request.FileChange.Changes, change)
		canonical.Changes = append(canonical.Changes, canonicalChange{Path: item.Path, Operation: item.Operation, ExpectedSHA256: expected, Content: content})
	}
	if toolrunner.ValidateRequest(request) != nil {
		return toolrunner.Request{}, nil, harnessprotocol.SafeContent{}, "", false
	}
	encoded, _ := json.Marshal(canonical)
	input, prompt := fileChangePreview(value)
	return request, encoded, input, prompt, true
}

const maximumSafePromptBytes = 1800

func commandPreview(value commandArguments) (harnessprotocol.SafeContent, string) {
	access := "только чтение"
	request := "Codex просит выполнить команду только для чтения в изолированной рабочей папке диалога."
	if value.Access == toolrunner.AccessWrite {
		access = "с записью"
		request = "Codex просит выполнить команду с записью в изолированной рабочей папке диалога."
	}
	commandRedacted := containsSensitiveNativeOutput(value.Command)
	cwdRedacted := containsSensitiveNativeOutput(value.CWD)
	redacted := commandRedacted || cwdRedacted
	details := fmt.Sprintf("Доступ: %s\nКаталог: %s\nКоманда: %s", access, value.CWD, value.Command)
	if redacted {
		cwd := value.CWD
		if cwdRedacted {
			cwd = "скрыт"
		}
		details = fmt.Sprintf("Доступ: %s\nКаталог: %s\nКоманда содержит данные, скрытые политикой безопасности.", access, cwd)
	}
	inputText, inputTruncated := boundedPreview(details, "\n[описание сокращено]")
	promptText, _ := boundedPrompt(request+"\n"+details, "\nРазрешить один раз?")
	return harnessprotocol.SafeContent{Kind: "inline", Content: inputText, Redaction: redactionValue(redacted), Truncated: inputTruncated}, promptText
}

func fileChangePreview(value fileChangeArguments) (harnessprotocol.SafeContent, string) {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Операций с файлами: %d", len(value.Changes)))
	redacted := false
	for _, change := range value.Changes {
		if containsSensitiveNativeOutput(change.Path) {
			redacted = true
			break
		}
		fmt.Fprintf(&builder, "\n- %s: %s", fileOperationLabel(change.Operation), change.Path)
	}
	if redacted {
		builder.Reset()
		fmt.Fprintf(&builder, "Операций с файлами: %d\nПути скрыты политикой безопасности.", len(value.Changes))
	}
	details := builder.String()
	inputText, inputTruncated := boundedPreview(details, "\n[описание сокращено]")
	promptText, _ := boundedPrompt("Codex просит изменить файлы в изолированной рабочей папке диалога.\n"+details, "\nРазрешить один раз?")
	return harnessprotocol.SafeContent{Kind: "inline", Content: inputText, Redaction: redactionValue(redacted), Truncated: inputTruncated}, promptText
}

func boundedPreview(value, marker string) (string, bool) {
	if len(value) <= maximumSafePromptBytes {
		return value, false
	}
	return truncateUTF8(value, maximumSafePromptBytes-len(marker)) + marker, true
}

func boundedPrompt(value, suffix string) (string, bool) {
	if len(value)+len(suffix) <= maximumSafePromptBytes {
		return value + suffix, false
	}
	marker := "\n[описание сокращено]"
	return truncateUTF8(value, maximumSafePromptBytes-len(marker)-len(suffix)) + marker + suffix, true
}

func redactionValue(redacted bool) string {
	if redacted {
		return "applied"
	}
	return "none"
}

func fileOperationLabel(operation toolrunner.FileOperation) string {
	if operation == toolrunner.FileDelete {
		return "Удаление"
	}
	return "Запись"
}

func decodeStrict(encoded json.RawMessage, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
}

func rawJSONNullableString(encoded json.RawMessage, target **string) bool {
	trimmed := bytes.TrimSpace(encoded)
	if len(trimmed) == 0 {
		return false
	}
	if bytes.Equal(trimmed, []byte("null")) {
		*target = nil
		return true
	}
	var value string
	if json.Unmarshal(trimmed, &value) != nil || !utf8.ValidString(value) {
		return false
	}
	*target = &value
	return true
}

func dynamicActionHash(native *nativeAttempt, itemID, tool string, arguments []byte) string {
	encoded, err := json.Marshal(struct {
		Version      int             `json:"version"`
		NodeID       string          `json:"nodeId"`
		DialogID     string          `json:"dialogId"`
		RequestID    string          `json:"requestId"`
		AttemptID    string          `json:"attemptId"`
		Generation   int64           `json:"generation"`
		PolicyHash   string          `json:"policyHash"`
		ProviderCall string          `json:"providerCallId"`
		Namespace    string          `json:"namespace"`
		Tool         string          `json:"tool"`
		Arguments    json.RawMessage `json:"arguments"`
	}{
		Version: 1, NodeID: native.reference.NodeID, DialogID: native.reference.DialogID,
		RequestID: native.reference.RequestID, AttemptID: native.reference.AttemptID, Generation: native.reference.Generation,
		PolicyHash: native.policyHash, ProviderCall: itemID, Namespace: "codex", Tool: tool, Arguments: arguments,
	})
	if err != nil {
		return ""
	}
	return digestString("codex-dynamic-action-v1\x00" + string(encoded))
}

func sameDynamicResponse(expected nativeDynamicToolResponse, content []nativeDynamicContentItem, success bool) bool {
	if expected.Success != success || len(expected.ContentItems) != len(content) {
		return false
	}
	for index := range content {
		if expected.ContentItems[index] != content[index] {
			return false
		}
	}
	return true
}

func safeDynamicResponse(response nativeDynamicToolResponse) harnessprotocol.SafeContent {
	if len(response.ContentItems) != 1 || response.ContentItems[0].Type != "inputText" {
		return unavailableContent("provider_redacted")
	}
	return safeNativeOutput(response.ContentItems[0].Text, false)
}

func safeRunnerResponse(result toolrunner.Result, runErr error) nativeDynamicToolResponse {
	if runErr != nil {
		return failedDynamicResponse()
	}
	content := safeNativeOutput(string(result.Output), result.Truncated)
	text := "Инструмент завершён без вывода."
	if content.Kind == "inline" {
		text = content.Content
		if text == "" {
			text = "Инструмент завершён без вывода."
		}
		if content.Truncated {
			marker := "\n[output truncated]"
			text = truncateUTF8(text, maximumNativeToolOutput-len(marker)) + marker
		}
	} else {
		text = "Вывод инструмента скрыт политикой безопасности."
	}
	if len(result.Changes) > 0 {
		if result.Success {
			text = fmt.Sprintf("Операции с файлами выполнены: %d.", len(result.Changes))
		} else {
			text = fmt.Sprintf("Операции с файлами завершились с ошибкой после применённых изменений: %d.", len(result.Changes))
		}
	}
	return nativeDynamicToolResponse{Success: result.Success, ContentItems: []nativeDynamicContentItem{{Type: "inputText", Text: text}}}
}

func safeRunnerFullText(result toolrunner.Result, runErr error) (*string, bool) {
	if runErr != nil || len(result.Changes) > 0 || !utf8.Valid(result.Output) {
		return nil, false
	}
	value := string(result.Output)
	if containsSensitiveNativeOutput(value) {
		return nil, false
	}
	if value == "" {
		value = "Инструмент завершён без вывода."
	}
	return &value, result.Truncated
}

func (adapter *Adapter) setExpectedToolResponse(native *nativeAttempt, itemID string, response nativeDynamicToolResponse, effectStatus string, outputTruncated bool, fullSafeOutput *string, fullIncomplete bool) bool {
	native.mu.Lock()
	defer native.mu.Unlock()
	tool, ok := native.tools[itemID]
	if !ok || tool.done || tool.expectedResponse != nil {
		return false
	}
	copyResponse := response
	tool.expectedResponse = &copyResponse
	tool.effectStatus = effectStatus
	tool.outputTruncated = outputTruncated
	if fullSafeOutput != nil {
		copyFull := *fullSafeOutput
		tool.fullSafeOutput = &copyFull
	}
	tool.fullIncomplete = fullIncomplete
	native.tools[itemID] = tool
	return true
}

func pushOutputLimit(native *nativeAttempt, callID string, index int64) {
	native.runtime.push(harnessadapter.ToolOutputEvent{
		EventBase: harnessadapter.EventBase{Attempt: native.reference}, CallID: callID,
		ChunkIndex: index, Stream: "diagnostic", Output: unavailableContent("output_limit"),
	})
}

func truncateUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for value != "" && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

var nativeSecretPattern = regexp.MustCompile(`(?i)(^|[[:space:]{\[,(;])["']?(api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|credential|private[-_]?key|auth)["']?[[:space:]]*[:=]`)
var nativeEnvironmentSecretPattern = regexp.MustCompile(`(?i)\b(?:[A-Z0-9]+[_-])*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|SESSION[_-]?TOKEN|TOKEN|PASSWORD|PASSWD|CLIENT[_-]?SECRET|SECRET(?:[_-]?ACCESS[_-]?KEY)?|PRIVATE[_-]?KEY)["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{8,}`)
var nativeStandaloneTokenPattern = regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(sk-[a-z0-9_-]{4,}|gh[pousr]_[a-z0-9]{8,})($|[^a-z0-9_-])`)
var nativeJWTTokenPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})($|[^A-Za-z0-9_-])`)
var nativeCredentialURLPattern = regexp.MustCompile(`(?i)\bhttps?://[^\s/?#@]+:[^\s/?#@]+@`)

func safeNativeOutput(value string, alreadyTruncated bool) harnessprotocol.SafeContent {
	if !utf8.ValidString(value) || containsSensitiveNativeOutput(value) {
		content := unavailableContent("provider_redacted")
		content.Redaction = "applied"
		content.Truncated = alreadyTruncated || len(value) > maximumNativeToolOutput
		return content
	}
	truncated := alreadyTruncated || len(value) > maximumNativeToolOutput
	value = truncateUTF8(value, maximumNativeToolOutput)
	return harnessprotocol.SafeContent{Kind: "inline", Content: value, Redaction: "none", Truncated: truncated}
}

func containsSensitiveNativeOutput(value string) bool {
	lower := strings.ToLower(value)
	return nativeSecretPattern.MatchString(value) || nativeEnvironmentSecretPattern.MatchString(value) || nativeStandaloneTokenPattern.MatchString(value) || nativeJWTTokenPattern.MatchString(value) ||
		nativeCredentialURLPattern.MatchString(value) || strings.Contains(lower, "-----begin private key-----") ||
		strings.Contains(lower, "-----begin rsa private key-----") || strings.Contains(lower, "bearer ")
}

func redactedInline(value string) harnessprotocol.SafeContent {
	return harnessprotocol.SafeContent{Kind: "inline", Content: value, Redaction: "applied", Truncated: false}
}

func (adapter *Adapter) handleUsage(native *nativeAttempt, usage nativeUsage) {
	if !validNativeUsage(usage) {
		native.runtime.failUnknown("adapter_protocol")
		return
	}
	mapped := &harnessprotocol.Usage{Source: "per_attempt", InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens, TotalTokens: usage.TotalTokens}
	native.mu.Lock()
	native.usage = mapped
	native.mu.Unlock()
}

func (adapter *Adapter) finish(native *nativeAttempt, status string) {
	native.cancelTools()
	inputUnconfirmed := adapter.resolveAttemptInputs(native, false)
	approvalUnconfirmed := adapter.resolveAttemptApprovals(native, false)
	if inputUnconfirmed || approvalUnconfirmed || native.hasOpenTools() {
		native.runtime.failUnknown("provider_state")
		_ = adapter.store.terminal(native.reference)
		return
	}
	native.mu.Lock()
	output, usage := native.output, native.usage
	if output != nil {
		copyOutput := *output
		output = &copyOutput
	}
	if usage != nil {
		copyUsage := *usage
		usage = &copyUsage
	}
	native.mu.Unlock()
	base := harnessadapter.EventBase{Attempt: native.reference}
	switch status {
	case "completed":
		result := harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileCompleted, Output: output, Usage: usage, EffectStatus: "known"}
		native.runtime.finish(result, harnessadapter.TerminalEvent{EventBase: base, Outcome: result.Outcome, Output: output, Usage: usage, EffectStatus: result.EffectStatus})
	case "interrupted":
		result := harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileInterrupted, Usage: usage, EffectStatus: "known"}
		native.runtime.finish(result, harnessadapter.TerminalEvent{EventBase: base, Outcome: result.Outcome, Usage: usage, EffectStatus: result.EffectStatus})
	case "failed":
		failure := taskFailure("codex_turn_failed", "codex turn failed")
		result := harnessadapter.ReconcileResult{Outcome: harnessadapter.ReconcileFailed, Usage: usage, Failure: failure, EffectStatus: "unknown"}
		native.runtime.finish(result, harnessadapter.TerminalEvent{EventBase: base, Outcome: result.Outcome, Usage: usage, Failure: failure, EffectStatus: result.EffectStatus})
	default:
		native.runtime.failUnknown("provider_state")
	}
	_ = adapter.store.terminal(native.reference)
}

func (adapter *Adapter) handleExit() { adapter.failActive("provider_state") }

func (adapter *Adapter) failActive(reason string) {
	adapter.mu.Lock()
	attempts := make([]*nativeAttempt, 0, len(adapter.attempts))
	for _, native := range adapter.attempts {
		attempts = append(attempts, native)
	}
	adapter.mu.Unlock()
	for _, native := range attempts {
		native.cancelTools()
		adapter.resolveAttemptInputs(native, false)
		adapter.resolveAttemptApprovals(native, false)
		outcome := native.runtime.reconcile().Outcome
		if outcome == harnessadapter.ReconcileRunning || outcome == harnessadapter.ReconcileWaitingInput {
			native.runtime.failUnknown(reason)
		}
	}
}

func boundedQuestion(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
