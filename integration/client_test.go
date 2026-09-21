package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	hp "github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

type apiFault struct {
	Status int
	Code   string
}

func (f *apiFault) Error() string { return f.Code }

type apiResponse struct {
	Status int
	Body   []byte
}

type binaryResponse struct {
	Metadata     hp.ArtifactMetadata
	Body         []byte
	Status       int
	ContentRange string
}

// testAPIClient is intentionally local to the producer repository. It proves
// the private mTLS/pinned-peer wire without importing a Panel/Router consumer.
type testAPIClient struct {
	baseURL string
	nodeID  string
	client  *http.Client
}

func newTestAPIClient(baseURL, nodeID string, roots *x509.CertPool, serverCert, clientCert tls.Certificate) *testAPIClient {
	wantPin := sha256.Sum256(serverCert.Certificate[0])
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing peer certificate")
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], wantPin[:]) {
				return fmt.Errorf("server certificate pin mismatch")
			}
			return nil
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true}
	return &testAPIClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		nodeID:  nodeID,
		client:  &http.Client{Transport: transport},
	}
}

func (c *testAPIClient) Close() { c.client.CloseIdleConnections() }

func (c *testAPIClient) request(ctx context.Context, method, path, owner, accept, byteRange string, body []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Harness-Actor-ID", owner)
	request.Header.Set("Accept", accept)
	if byteRange != "" {
		request.Header.Set("Range", byteRange)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(request)
}

func boundedJSON(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return nil, fmt.Errorf("invalid JSON response headers")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, hp.MaximumWireBytes+1))
	if err != nil || len(body) > hp.MaximumWireBytes {
		return nil, fmt.Errorf("invalid JSON response body")
	}
	return body, nil
}

func (c *testAPIClient) Read(ctx context.Context, nodeID, owner, path, query string) (apiResponse, error) {
	upstream := "/v1/nodes/" + nodeID + "/" + path
	if strings.HasPrefix(path, "health/") {
		upstream = "/" + path
	}
	if query != "" {
		upstream += "?" + query
	}
	response, err := c.request(ctx, http.MethodGet, upstream, owner, "application/json", "", nil)
	if err != nil {
		return apiResponse{}, err
	}
	body, err := boundedJSON(response)
	if err != nil {
		return apiResponse{}, err
	}
	return apiResponse{Status: response.StatusCode, Body: body}, nil
}

func (c *testAPIClient) Command(ctx context.Context, nodeID, owner string, body []byte) (apiResponse, error) {
	var command hp.CommandEnvelope
	if json.Unmarshal(body, &command) != nil {
		return apiResponse{}, fmt.Errorf("invalid command")
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/nodes/"+nodeID+"/commands", owner, "application/json", "", body)
	if err == nil {
		result, readErr := boundedJSON(response)
		if readErr == nil {
			return apiResponse{Status: response.StatusCode, Body: result}, nil
		}
	}
	// A lost acknowledgement is reconciled by command ID; bytes are never resent.
	status, readErr := c.Read(ctx, nodeID, owner, "commands/"+url.PathEscape(command.CommandID), "")
	if readErr != nil || status.Status != http.StatusOK {
		if err != nil {
			return apiResponse{}, err
		}
		return apiResponse{}, readErr
	}
	var proof hp.CommandStatus
	if json.Unmarshal(status.Body, &proof) != nil || proof.Status != "accepted" {
		return apiResponse{}, fmt.Errorf("invalid command reconciliation")
	}
	receipt, marshalErr := json.Marshal(proof.Receipt)
	if marshalErr != nil {
		return apiResponse{}, marshalErr
	}
	return apiResponse{Status: http.StatusAccepted, Body: receipt}, nil
}

type testEventStream struct {
	mu      sync.Mutex
	body    io.ReadCloser
	scanner *bufio.Scanner
	closed  bool
}

func (c *testAPIClient) OpenEvents(ctx context.Context, nodeID, owner string, after int64) (*testEventStream, error) {
	response, err := c.request(ctx, http.MethodGet,
		"/v1/nodes/"+nodeID+"/events?after="+strconv.FormatInt(after, 10), owner, "text/event-stream", "", nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		body, readErr := boundedJSON(response)
		return nil, fmt.Errorf("event stream rejected: %d %s: %v", response.StatusCode, body, readErr)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 16<<10), hp.MaximumWireBytes+1024)
	return &testEventStream{body: response.Body, scanner: scanner}, nil
}

func (s *testEventStream) Next() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var data []byte
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			if data != nil {
				return data, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			data = []byte(strings.TrimPrefix(line, "data: "))
		}
	}
	if err := s.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (s *testEventStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.body.Close()
}

func (c *testAPIClient) Artifact(ctx context.Context, nodeID, owner, artifactID, byteRange string) (binaryResponse, error) {
	metadataResponse, err := c.Read(ctx, nodeID, owner, "artifacts/"+artifactID+"/metadata", "")
	if err != nil {
		return binaryResponse{}, err
	}
	if metadataResponse.Status != http.StatusOK {
		var failure hp.Error
		_ = json.Unmarshal(metadataResponse.Body, &failure)
		return binaryResponse{}, &apiFault{Status: metadataResponse.Status, Code: failure.Code}
	}
	var metadata hp.ArtifactMetadata
	if json.Unmarshal(metadataResponse.Body, &metadata) != nil {
		return binaryResponse{}, fmt.Errorf("invalid artifact metadata")
	}
	response, err := c.request(ctx, http.MethodGet, "/v1/nodes/"+nodeID+"/artifacts/"+artifactID, owner, "application/octet-stream", byteRange, nil)
	if err != nil {
		return binaryResponse{}, err
	}
	if response.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		response.Body.Close()
		return binaryResponse{}, &apiFault{Status: response.StatusCode, Code: "range_not_satisfiable"}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		body, readErr := boundedJSON(response)
		if readErr != nil {
			return binaryResponse{}, readErr
		}
		var failure hp.Error
		_ = json.Unmarshal(body, &failure)
		return binaryResponse{}, &apiFault{Status: response.StatusCode, Code: failure.Code}
	}
	defer response.Body.Close()
	expectedBytes := metadata.SizeBytes
	wantContentRange := ""
	if byteRange != "" {
		var start, end int64
		if _, scanErr := fmt.Sscanf(byteRange, "bytes=%d-%d", &start, &end); scanErr != nil || start < 0 || end < start || end >= metadata.SizeBytes {
			return binaryResponse{}, fmt.Errorf("invalid range")
		}
		expectedBytes = end - start + 1
		wantContentRange = fmt.Sprintf("bytes %d-%d/%d", start, end, metadata.SizeBytes)
		if response.StatusCode != http.StatusPartialContent || response.Header.Get("Content-Range") != wantContentRange {
			return binaryResponse{}, fmt.Errorf("invalid range response")
		}
	} else if response.StatusCode != http.StatusOK || response.Header.Get("Content-Range") != "" {
		return binaryResponse{}, fmt.Errorf("invalid full artifact response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, expectedBytes+1))
	if err != nil || int64(len(body)) != expectedBytes {
		return binaryResponse{}, &apiFault{Status: http.StatusServiceUnavailable, Code: "not_durable"}
	}
	if byteRange == "" {
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != metadata.SHA256 {
			return binaryResponse{}, &apiFault{Status: http.StatusServiceUnavailable, Code: "not_durable"}
		}
	}
	return binaryResponse{Metadata: metadata, Body: body, Status: response.StatusCode, ContentRange: wantContentRange}, nil
}
