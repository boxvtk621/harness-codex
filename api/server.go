// Package server exposes the private Harness HTTP boundary.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boxvtk621/harness-codex/internal/harnessbarrier"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
	"github.com/boxvtk621/harness-codex/internal/historyreplica"
	"github.com/boxvtk621/harness-codex/internal/providerauth"
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
	"github.com/boxvtk621/harness-codex/runtime"
)

type Config struct {
	NodeID string
}

func New(config Config, authority *node.Node) (http.Handler, error) {
	if authority == nil || config.NodeID == "" || authority.NodeID() != config.NodeID {
		return nil, errors.New("server config is incomplete")
	}
	server := &Server{config: config, node: authority}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", server.live)
	mux.HandleFunc("GET /health/ready", server.ready)
	mux.HandleFunc("GET /v1/identity", server.identity)
	mux.HandleFunc("GET /v1/provider-auth", server.providerAuth)
	mux.HandleFunc("POST /v1/provider-auth/check", server.providerAuthCheck)
	mux.HandleFunc("POST /v1/provider-auth/operations", server.providerAuthStart)
	mux.HandleFunc("GET /v1/provider-auth/operations/{operationId}", server.providerAuthOperation)
	mux.HandleFunc("POST /v1/provider-auth/operations/{operationId}/cancel", server.providerAuthCancel)
	mux.HandleFunc("POST /v1/provider-auth/logout", server.providerAuthLogout)
	mux.HandleFunc("GET /v1/executor/heartbeat", server.executorHeartbeat)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/identity", server.identity)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/admission", server.admission)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/snapshot", server.snapshot)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/dialogs", server.dialogs)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/dialogs/{dialogId}/messages", server.history)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/dialogs/{dialogId}/history-export", server.historyExport)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/requests", server.requests)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/requests/{requestId}/attempts", server.attempts)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/attempts/{attemptId}", server.attempt)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/attempts/{attemptId}/events", server.attemptEvents)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/artifacts/{artifactId}/metadata", server.artifactMetadata)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/artifacts/{artifactId}", server.artifact)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/texts/resolve", server.safeTextManifest)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/texts/{textId}/chunks/{chunkIndex}", server.safeTextChunk)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/events", server.events)
	mux.HandleFunc("POST /v1/nodes/{nodeId}/commands", server.command)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/commands/{commandId}", server.commandStatus)
	mux.HandleFunc("POST /v1/nodes/{nodeId}/administration/holds", server.installHold)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/administration/holds/{operationId}/proof", server.quiescenceProof)
	mux.HandleFunc("POST /v1/nodes/{nodeId}/administration/holds/{operationId}/release", server.releaseHold)
	mux.HandleFunc("POST /v1/nodes/{nodeId}/administration/logical-deletes", server.logicalDelete)
	mux.HandleFunc("GET /v1/nodes/{nodeId}/administration/logical-deletes/{operationId}", server.logicalDeleteStatus)
	server.handler = mux
	return server, nil
}

type providerAuthCommandRequest struct {
	NodeID    string `json:"nodeId"`
	CommandID string `json:"commandId"`
}

type providerAuthStartRequest struct {
	NodeID    string          `json:"nodeId"`
	CommandID string          `json:"commandId"`
	Method    string          `json:"method"`
	Secret    json.RawMessage `json:"secret,omitempty"`
}

func (server *Server) providerAuth(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request, "nodeId") || !providerauth.UUIDPattern.MatchString(request.URL.Query().Get("nodeId")) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	writeResult(writer, server.node.ProviderAuthSnapshot(request.Context(), request.URL.Query().Get("nodeId")))
}

func (server *Server) providerAuthOperation(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request, "nodeId") || !providerauth.UUIDPattern.MatchString(request.URL.Query().Get("nodeId")) ||
		!providerauth.UUIDPattern.MatchString(request.PathValue("operationId")) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	writeResult(writer, server.node.ProviderAuthOperation(request.Context(), request.URL.Query().Get("nodeId"), request.PathValue("operationId")))
}

func (server *Server) providerAuthStart(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	var input providerAuthStartRequest
	if !decodeProviderAuthJSON(writer, request, &input) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	if !providerauth.UUIDPattern.MatchString(input.NodeID) || !providerauth.UUIDPattern.MatchString(input.CommandID) || input.Method == "" {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	var secret *string
	if len(input.Secret) > 0 {
		var value string
		if json.Unmarshal(input.Secret, &value) != nil || value == "" {
			writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
			return
		}
		secret = &value
	}
	writeResult(writer, server.node.ProviderAuthStart(request.Context(), input.NodeID, input.CommandID, input.Method, secret))
}

func (server *Server) providerAuthCheck(writer http.ResponseWriter, request *http.Request) {
	server.providerAuthCommand(writer, request, "check")
}

func (server *Server) providerAuthLogout(writer http.ResponseWriter, request *http.Request) {
	server.providerAuthCommand(writer, request, "logout")
}

func (server *Server) providerAuthCommand(writer http.ResponseWriter, request *http.Request, action string) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	var input providerAuthCommandRequest
	if !decodeProviderAuthJSON(writer, request, &input) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	if !providerauth.UUIDPattern.MatchString(input.NodeID) || !providerauth.UUIDPattern.MatchString(input.CommandID) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	if action == "check" {
		writeResult(writer, server.node.ProviderAuthCheck(request.Context(), input.NodeID, input.CommandID))
		return
	}
	writeResult(writer, server.node.ProviderAuthLogout(request.Context(), input.NodeID, input.CommandID))
}

func (server *Server) providerAuthCancel(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	var input providerAuthCommandRequest
	if !decodeProviderAuthJSON(writer, request, &input) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	if !providerauth.UUIDPattern.MatchString(input.NodeID) || !providerauth.UUIDPattern.MatchString(input.CommandID) ||
		!providerauth.UUIDPattern.MatchString(request.PathValue("operationId")) {
		writeResult(writer, providerAuthErrorResult(http.StatusBadRequest, "invalid_request"))
		return
	}
	writeResult(writer, server.node.ProviderAuthCancel(request.Context(), input.NodeID, input.CommandID, request.PathValue("operationId")))
}

func decodeProviderAuthJSON(writer http.ResponseWriter, request *http.Request, output any) bool {
	if contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type")); err != nil || contentType != "application/json" {
		return false
	}
	reader := http.MaxBytesReader(writer, request.Body, 64<<10)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func providerAuthErrorResult(status int, code string) node.Result {
	body, _ := json.Marshal(struct {
		Code string `json:"code"`
	}{Code: code})
	return node.Result{HTTPStatus: status, Body: body}
}

func queryLimit(request *http.Request) (int, bool) {
	value := request.URL.Query().Get("limit")
	if value == "" {
		return 0, true
	}
	limit, err := strconv.Atoi(value)
	return limit, err == nil && strconv.Itoa(limit) == value && limit >= 1 && limit <= harnessprotocol.MaximumPageSize
}

func validQuery(request *http.Request, allowed ...string) bool {
	permitted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		permitted[key] = true
	}
	for key, values := range request.URL.Query() {
		if !permitted[key] || len(values) != 1 || values[0] == "" {
			return false
		}
	}
	return true
}

func expectedIdentity(request *http.Request) (*harnessprotocol.NodeIdentity, bool) {
	headers := []string{
		harnessprotocol.ExpectedNodeIDHeader,
		harnessprotocol.ExpectedRegistryHeader,
		harnessprotocol.ExpectedEpochHeader,
		harnessprotocol.ExpectedAdapterKindHeader,
		harnessprotocol.ExpectedAdapterVersionHeader,
	}
	values := make([]string, len(headers))
	present := 0
	for index, name := range headers {
		all := request.Header.Values(name)
		if len(all) == 0 {
			continue
		}
		if len(all) != 1 || all[0] == "" || len(all[0]) > 200 || strings.TrimSpace(all[0]) != all[0] {
			return nil, false
		}
		values[index] = all[0]
		present++
	}
	if present == 0 {
		return nil, true
	}
	if present != len(headers) {
		return nil, false
	}
	registry, registryErr := strconv.ParseInt(values[1], 10, 64)
	epoch, epochErr := strconv.ParseInt(values[2], 10, 64)
	if registryErr != nil || epochErr != nil || registry < 1 || registry > harnessprotocol.MaximumSafeInteger ||
		epoch < 1 || epoch > harnessprotocol.MaximumSafeInteger || strconv.FormatInt(registry, 10) != values[1] ||
		strconv.FormatInt(epoch, 10) != values[2] || (values[3] != "cursor" && values[3] != "codex") {
		return nil, false
	}
	return &harnessprotocol.NodeIdentity{
		NodeID: values[0], RegistryVersion: registry, IdentityEpoch: epoch,
		Adapter: harnessprotocol.AdapterIdentity{Kind: values[3], Version: values[4]},
	}, true
}

func (server *Server) dialogs(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "cursor", "limit") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	limit, ok := queryLimit(request)
	if !ok {
		writeResult(writer, server.node.Invalid("limit is invalid"))
		return
	}
	writeResult(writer, server.node.Dialogs(request.Context(), trust, request.URL.Query().Get("cursor"), limit))
}

func (server *Server) history(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "cursor", "limit") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	limit, ok := queryLimit(request)
	if !ok {
		writeResult(writer, server.node.Invalid("limit is invalid"))
		return
	}
	writeResult(writer, server.node.History(request.Context(), trust, request.PathValue("dialogId"), request.URL.Query().Get("cursor"), limit))
}

func (server *Server) historyExport(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "logicalDialogId", "bindingGeneration", "afterSeq", "limit") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	query := request.URL.Query()
	parse := func(name string, defaultValue int64) (int64, bool) {
		value := query.Get(name)
		if value == "" {
			return defaultValue, true
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil && strconv.FormatInt(parsed, 10) == value
	}
	binding, bindingOK := parse("bindingGeneration", 0)
	after, afterOK := parse("afterSeq", 0)
	limit, limitOK := parse("limit", historyreplica.MaximumPageSize)
	identity := historyreplica.StreamIdentity{
		OwnerID: server.node.OwnerID(), LogicalDialogID: query.Get("logicalDialogId"), NodeID: request.PathValue("nodeId"),
		NodeDialogID: request.PathValue("dialogId"), BindingGeneration: binding,
	}
	if !bindingOK || !afterOK || !limitOK {
		writeResult(writer, server.node.Invalid("history export query is invalid"))
		return
	}
	writeResult(writer, server.node.ExportHistory(request.Context(), trust, identity, after, int(limit)))
}

func (server *Server) requests(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "cursor", "limit", "state") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	limit, ok := queryLimit(request)
	if !ok {
		writeResult(writer, server.node.Invalid("limit is invalid"))
		return
	}
	writeResult(writer, server.node.Requests(request.Context(), trust, request.URL.Query().Get("state"), request.URL.Query().Get("cursor"), limit))
}

func (server *Server) attempts(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "cursor", "limit") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	limit, ok := queryLimit(request)
	if !ok {
		writeResult(writer, server.node.Invalid("limit is invalid"))
		return
	}
	writeResult(writer, server.node.Attempts(request.Context(), trust, request.PathValue("requestId"), request.URL.Query().Get("cursor"), limit))
}

func (server *Server) attempt(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.Attempt(request.Context(), trust, request.PathValue("attemptId")))
}

func (server *Server) attemptEvents(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "after", "limit") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	limit, ok := queryLimit(request)
	if !ok {
		writeResult(writer, server.node.Invalid("limit is invalid"))
		return
	}
	after := int64(0)
	if value := request.URL.Query().Get("after"); value != "" {
		var valid bool
		after, valid = parseSafeInteger(value)
		if !valid {
			writeResult(writer, server.node.Invalid("event cursor is invalid"))
			return
		}
	}
	writeResult(writer, server.node.AttemptEvents(request.Context(), trust, request.PathValue("attemptId"), after, limit))
}

func (server *Server) artifactMetadata(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.ArtifactMetadata(request.Context(), trust, request.PathValue("artifactId")))
}

func (server *Server) safeTextManifest(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	keys := []string{"dialogId", "attemptId", "sourceKind", "sourceId", "sourceIndex", "sourceStream"}
	if !validQuery(request, keys...) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	query := request.URL.Query()
	for _, key := range keys {
		if query.Get(key) == "" {
			writeResult(writer, server.node.Invalid("query is invalid"))
			return
		}
	}
	index, valid := parseSafeInteger(query.Get("sourceIndex"))
	if !valid {
		writeResult(writer, server.node.Invalid("transcript source is invalid"))
		return
	}
	source := transcriptview.Source{
		Kind: query.Get("sourceKind"), ID: query.Get("sourceId"), Index: index, Stream: query.Get("sourceStream"),
	}
	writeResult(writer, server.node.SafeTextManifest(request.Context(), trust, query.Get("dialogId"), query.Get("attemptId"), source))
}

func (server *Server) safeTextChunk(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	keys := []string{"dialogId", "attemptId", "sourceKind", "sourceId", "sourceIndex", "sourceStream", "artifactId", "sizeBytes", "sha256"}
	if !validQuery(request, keys...) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	query := request.URL.Query()
	for _, key := range keys {
		if query.Get(key) == "" {
			writeResult(writer, server.node.Invalid("query is invalid"))
			return
		}
	}
	sourceIndex, sourceIndexValid := parseSafeInteger(query.Get("sourceIndex"))
	chunkIndex, chunkIndexValid := parseSafeInteger(request.PathValue("chunkIndex"))
	sizeBytes, sizeValid := parseSafeInteger(query.Get("sizeBytes"))
	if !sourceIndexValid || !chunkIndexValid || !sizeValid {
		writeResult(writer, server.node.Invalid("transcript chunk is invalid"))
		return
	}
	source := transcriptview.Source{
		Kind: query.Get("sourceKind"), ID: query.Get("sourceId"), Index: sourceIndex, Stream: query.Get("sourceStream"),
	}
	blob, failure, ok := server.node.SafeTextChunk(
		request.Context(), trust, query.Get("dialogId"), query.Get("attemptId"), request.PathValue("textId"), source,
		chunkIndex, query.Get("artifactId"), sizeBytes, query.Get("sha256"),
	)
	if !ok {
		writeResult(writer, failure)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "safe-text-" + strconv.FormatInt(chunkIndex, 10) + ".txt"}))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", strconv.Itoa(len(blob.Bytes)))
	writer.Header().Set(transcriptview.TextIDHeader, blob.TextID)
	writer.Header().Set(transcriptview.ChunkIndexHeader, strconv.FormatInt(blob.Chunk.Index, 10))
	writer.Header().Set(transcriptview.ArtifactIDHeader, blob.Chunk.ArtifactID)
	writer.Header().Set(transcriptview.ChunkSHA256Header, blob.Chunk.SHA256)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(blob.Bytes)
}

func (server *Server) artifact(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	blob, failure, ok := server.node.Artifact(request.Context(), trust, request.PathValue("artifactId"))
	if !ok {
		writeResult(writer, failure)
		return
	}
	start, end, partial, valid := byteRange(request.Header.Get("Range"), int64(len(blob.Bytes)))
	if !valid {
		writer.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(int64(len(blob.Bytes)), 10))
		writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	writer.Header().Set("Content-Type", blob.Metadata.MediaType)
	writer.Header().Set("Content-Disposition", mime.FormatMediaType(blob.Metadata.Disposition, map[string]string{"filename": blob.Metadata.Name}))
	writer.Header().Set("Accept-Ranges", "bytes")
	writer.Header().Set("Cache-Control", "no-store")
	body := blob.Bytes
	if partial {
		writer.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.Itoa(len(body)))
		body = body[start : end+1]
		writer.WriteHeader(http.StatusPartialContent)
	} else {
		writer.WriteHeader(http.StatusOK)
	}
	_, _ = writer.Write(body)
}

func byteRange(value string, size int64) (int64, int64, bool, bool) {
	if value == "" {
		return 0, size - 1, false, true
	}
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") || size == 0 {
		return 0, 0, false, false
	}
	left, right, found := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !found {
		return 0, 0, false, false
	}
	if left == "" {
		n, ok := parseSafeInteger(right)
		if !ok || n == 0 {
			return 0, 0, false, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true, true
	}
	start, ok := parseSafeInteger(left)
	if !ok || start >= size {
		return 0, 0, false, false
	}
	end := size - 1
	if right != "" {
		end, ok = parseSafeInteger(right)
		if !ok || end < start {
			return 0, 0, false, false
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end, true, true
}

func parseSafeInteger(value string) (int64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && n <= harnessprotocol.MaximumSafeInteger
}

func (server *Server) events(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request, "after") {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	after, ok := parseSafeInteger(request.URL.Query().Get("after"))
	if !ok {
		writeResult(writer, server.node.Invalid("event cursor is invalid"))
		return
	}
	initial, failure, ok := server.node.ReplayEvents(request.Context(), trust, after, 100)
	if !ok {
		writeResult(writer, failure)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeResult(writer, server.node.Invalid("streaming is unavailable"))
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	last := after
	batch := initial
	heartbeat := time.NewTicker(15 * time.Second)
	poll := time.NewTicker(20 * time.Millisecond)
	defer heartbeat.Stop()
	defer poll.Stop()
	for {
		for _, raw := range batch.Events {
			var envelope struct {
				Seq int64 `json:"seq"`
			}
			if json.Unmarshal(raw, &envelope) != nil || envelope.Seq != last+1 {
				return
			}
			_, _ = writer.Write([]byte("id: " + strconv.FormatInt(envelope.Seq, 10) + "\ndata: "))
			_, _ = writer.Write(raw)
			_, _ = writer.Write([]byte("\n\n"))
			last = envelope.Seq
		}
		if len(batch.Events) > 0 {
			flusher.Flush()
		}
		select {
		case <-request.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = writer.Write([]byte(": keep-alive\n\n"))
			flusher.Flush()
		case <-poll.C:
		}
		var good bool
		batch, failure, good = server.node.ReplayEvents(request.Context(), trust, last, 100)
		if !good {
			return
		}
	}
}

type Server struct {
	config  Config
	node    *node.Node
	handler http.Handler
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *Server) authenticate(writer http.ResponseWriter, request *http.Request) (node.TrustContext, bool) {
	nodeID := request.PathValue("nodeId")
	if nodeID == "" {
		nodeID = server.config.NodeID
	}
	return node.TrustContext{TransportNodeID: nodeID}, true
}

func (server *Server) authenticateOperator(writer http.ResponseWriter, request *http.Request) (node.OperatorTrustContext, bool) {
	nodeID := request.PathValue("nodeId")
	if nodeID == "" {
		nodeID = server.config.NodeID
	}
	return node.OperatorTrustContext{TransportNodeID: nodeID}, true
}

func (server *Server) installHold(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticateOperator(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	reader := http.MaxBytesReader(writer, request.Body, harnessbarrier.MaximumWireBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		writeResult(writer, server.node.Invalid("hold request exceeds the wire limit"))
		return
	}
	writeResult(writer, server.node.InstallHold(request.Context(), trust, body))
}

func (server *Server) quiescenceProof(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticateOperator(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.QuiescenceProof(request.Context(), trust, request.PathValue("operationId")))
}

func (server *Server) releaseHold(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticateOperator(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	reader := http.MaxBytesReader(writer, request.Body, harnessbarrier.MaximumWireBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		writeResult(writer, server.node.Invalid("release request exceeds the wire limit"))
		return
	}
	var release harnessbarrier.ReleaseRequest
	if json.Unmarshal(body, &release) != nil || release.OperationID != request.PathValue("operationId") {
		writeResult(writer, server.node.Invalid("release operation does not match path"))
		return
	}
	writeResult(writer, server.node.ReleaseHold(request.Context(), trust, body))
}

func (server *Server) logicalDelete(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticateOperator(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	reader := http.MaxBytesReader(writer, request.Body, harnessbarrier.MaximumWireBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		writeResult(writer, server.node.Invalid("logical delete request exceeds the wire limit"))
		return
	}
	writeResult(writer, server.node.DeleteLogicalDialog(request.Context(), trust, body))
}

func (server *Server) logicalDeleteStatus(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticateOperator(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.LogicalDeleteStatus(request.Context(), trust, request.PathValue("operationId")))
}

func (server *Server) live(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.authenticate(writer, request); !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.HealthLive())
}

func (server *Server) ready(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.HealthReady(request.Context(), trust))
}

func (server *Server) identity(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.Identity(request.Context(), trust))
}

func (server *Server) executorHeartbeat(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.ExecutorHeartbeat(request.Context(), trust))
}

func (server *Server) admission(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.Admission(request.Context(), trust))
}

func (server *Server) snapshot(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.Snapshot(request.Context(), trust))
}

func (server *Server) commandStatus(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	writeResult(writer, server.node.CommandStatus(request.Context(), trust, request.PathValue("commandId")))
}

func (server *Server) command(writer http.ResponseWriter, request *http.Request) {
	trust, ok := server.authenticate(writer, request)
	if !ok {
		return
	}
	if !validQuery(request) {
		writeResult(writer, server.node.Invalid("query is invalid"))
		return
	}
	expected, ok := expectedIdentity(request)
	if !ok {
		writeResult(writer, server.node.Invalid("expected identity is invalid"))
		return
	}
	trust.ExpectedIdentity = expected
	reader := http.MaxBytesReader(writer, request.Body, harnessprotocol.MaximumWireBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		writeResult(writer, server.node.Invalid("command exceeds the wire limit"))
		return
	}
	writeResult(writer, server.node.SubmitCommand(request.Context(), trust, body))
}

func writeResult(writer http.ResponseWriter, result node.Result) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(result.HTTPStatus)
	_, _ = writer.Write(result.Body)
}
