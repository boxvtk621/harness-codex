// Package node implements the durable, single-writer Harness node authority.
package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/boxvtk621/harness-codex/internal/harnessadapter"
	"github.com/boxvtk621/harness-codex/internal/harnessprotocol"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const (
	SchemaVersion       = 6
	QueueCapacity       = 100
	ControlReserveBytes = 8 * 1024 * 1024
	MinimumFreeBytes    = 1 << 30
)

type IDSource interface {
	NewID() (string, error)
}

type randomIDs struct{}

func (randomIDs) NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	value := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", value[:8], value[8:12], value[12:16], value[16:20], value[20:]), nil
}

type PolicySource interface {
	Current(context.Context, string) (harnessadapter.PolicySnapshot, error)
}

type SpaceInfo struct {
	FreeBytes  uint64
	TotalBytes uint64
}

type SpaceProbe interface {
	Measure(string) (SpaceInfo, error)
}

type Config struct {
	DataDir         string
	NodeID          string
	OwnerID         string
	RegistryVersion int64
	Adapter         harnessadapter.Adapter
	Policies        PolicySource
	Clock           func() time.Time
	IDs             IDSource
	Space           SpaceProbe
	StartupFault    func(StartupPoint) error
	Artifacts       *ArtifactIngress
	// ManualDispatchForTesting keeps deterministic fixture setup under direct
	// DispatchNext control. Production configuration must leave it false.
	ManualDispatchForTesting bool
}

func (config *Config) defaults() error {
	if config.DataDir == "" || !uuidPattern.MatchString(config.NodeID) || config.OwnerID == "" ||
		!utf8.ValidString(config.OwnerID) || len([]rune(config.OwnerID)) > 200 || config.RegistryVersion <= 0 ||
		config.RegistryVersion > harnessprotocol.MaximumSafeInteger || config.Adapter == nil {
		return errors.New("node config is incomplete")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.IDs == nil {
		config.IDs = randomIDs{}
	}
	if config.Space == nil {
		config.Space = filesystemSpace{}
	}
	if config.Artifacts == nil {
		config.Artifacts = NewArtifactIngress()
	}
	return nil
}

type TrustContext struct {
	TransportNodeID string
	// ExpectedIdentity is supplied by the private HTTP boundary and is
	// compared with durable state under the node admission lock.
	ExpectedIdentity *harnessprotocol.NodeIdentity
}

type Result struct {
	HTTPStatus int
	Body       []byte
	Committed  bool
}

type FaultPoint string

const (
	FaultBeforeCommit              FaultPoint = "before_commit"
	FaultAfterCommit               FaultPoint = "after_commit"
	FaultAfterDispatchIntent       FaultPoint = "after_dispatch_intent"
	FaultBeforeHoldCommit          FaultPoint = "before_hold_commit"
	FaultAfterHoldCommit           FaultPoint = "after_hold_commit"
	FaultBeforeRejectionCommit     FaultPoint = "before_rejection_commit"
	FaultAfterRejectionCommit      FaultPoint = "after_rejection_commit"
	FaultBeforeReleaseCommit       FaultPoint = "before_release_commit"
	FaultAfterReleaseCommit        FaultPoint = "after_release_commit"
	FaultBeforeLogicalDeleteCommit FaultPoint = "before_logical_delete_commit"
	FaultAfterLogicalDeleteCommit  FaultPoint = "after_logical_delete_commit"
)

// FaultInjector is test-only. Production configuration leaves it nil.
type FaultInjector func(FaultPoint) error

type StartupPoint string

const (
	StartupReserveWrite    StartupPoint = "reserve_write"
	StartupReserveSync     StartupPoint = "reserve_sync"
	StartupBeforeMigration StartupPoint = "before_migration"
	StartupDuringMigration StartupPoint = "during_migration"
	StartupAfterMigration  StartupPoint = "after_migration"
)
