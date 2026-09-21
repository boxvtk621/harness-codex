// Package server exposes the private mTLS Harness HTTP boundary.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	"github.com/boxvtk621/harness-codex/internal/transcriptview"
	"github.com/boxvtk621/harness-codex/runtime"
)

const DefaultActorHeader = "X-Harness-Actor-ID"

type Config struct {
	NodeID                    string
	GatewayCertificateSHA256  string
	OperatorCertificateSHA256 string
	ActorHeader               string
}

func New(config Config, authority *node.Node) (http.Handler, error) {
	if authority == nil || config.NodeID == "" || authority.NodeID() != config.NodeID {
		return nil, errors.New("server config is incomplete")
	}
	pin, err := hex.DecodeString(config.GatewayCertificateSHA256)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("gateway certificate SHA-256 pin is invalid")
	}
	var operatorPin []byte
	if config.OperatorCertificateSHA256 != "" {
		operatorPin, err = hex.DecodeString(config.OperatorCertificateSHA256)
		if err != nil || len(operatorPin) != sha256.Size {
			return nil, errors.New("operator certificate SHA-256 pin is invalid")
		}
	}
	if config.ActorHeader == "" {
		config.ActorHeader = DefaultActorHeader
	}
	if strings.ContainsAny(config.ActorHeader, "\r\n") {
		return nil, errors.New("actor header is invalid")
	}
	server := &Server{config: config, node: authority, gatewayPin: pin, operatorPin: operatorPin}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", server.live)
	mux.HandleFunc("GET /health/ready", server.ready)
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
		OwnerID: trust.ActorID, LogicalDialogID: query.Get("logicalDialogId"), NodeID: request.PathValue("nodeId"),
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
	config      Config
	node        *node.Node
	gatewayPin  []byte
	operatorPin []byte
	handler     http.Handler
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *Server) trust(request *http.Request) (node.TrustContext, bool) {
	return server.trustWithPin(request, server.gatewayPin)
}

func (server *Server) trustWithPin(request *http.Request, pin []byte) (node.TrustContext, bool) {
	if request.TLS == nil || !request.TLS.HandshakeComplete || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return node.TrustContext{}, false
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].Raw)
	if len(pin) != sha256.Size || subtle.ConstantTimeCompare(digest[:], pin) != 1 {
		return node.TrustContext{}, false
	}
	actor := request.Header.Get(server.config.ActorHeader)
	if actor == "" {
		return node.TrustContext{}, false
	}
	transportNodeID := request.PathValue("nodeId")
	if transportNodeID == "" {
		transportNodeID = server.config.NodeID
	}
	return node.TrustContext{ActorID: actor, TransportNodeID: transportNodeID, PeerVerified: true}, true
}

func (server *Server) authenticate(writer http.ResponseWriter, request *http.Request) (node.TrustContext, bool) {
	trust, ok := server.trust(request)
	if ok {
		return trust, true
	}
	writeResult(writer, server.node.Forbidden())
	return node.TrustContext{}, false
}

func (server *Server) authenticateOperator(writer http.ResponseWriter, request *http.Request) (node.OperatorTrustContext, bool) {
	trust, ok := server.trustWithPin(request, server.operatorPin)
	if !ok {
		writeResult(writer, server.node.Forbidden())
		return node.OperatorTrustContext{}, false
	}
	return node.OperatorTrustContext{ActorID: trust.ActorID, TransportNodeID: trust.TransportNodeID, PeerVerified: trust.PeerVerified}, true
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
