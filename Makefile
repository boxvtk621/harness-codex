SHELL := /bin/sh
IMAGE ?= harness-codex:local
SOURCE_REPO ?=
PYTHON ?= python3
GO_TEST_IMAGE ?= golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd

.PHONY: quality provenance boundaries contracts fmt-check go-quality physical-enospc deterministic-build image smoke

quality: provenance boundaries contracts fmt-check go-quality physical-enospc deterministic-build

provenance:
	@test -n "$(SOURCE_REPO)" || { echo 'SOURCE_REPO must point to homelab-telegram-panel at the pinned source commit' >&2; exit 2; }
	$(PYTHON) scripts/verify_provenance.py --source "$(SOURCE_REPO)"
	$(PYTHON) scripts/test_verify_provenance.py

boundaries:
	$(PYTHON) scripts/check_boundaries.py
	GOWORK=off go list -deps ./... >/dev/null

contracts:
	npm ci --ignore-scripts --no-audit --no-fund
	npm run contracts

fmt-check:
	@test -z "$$(gofmt -l $$(find adapters api cmd fixture integration internal runtime -name '*.go' -type f))"

go-quality:
	GOWORK=off go vet ./...
	GOWORK=off go test -race ./...

physical-enospc:
	docker run --rm --tmpfs /scratch:rw,nosuid,nodev,size=32m -e GOWORK=off -v "$(CURDIR):/src:ro" -w /src "$(GO_TEST_IMAGE)" sh -c "go test -c -o /tmp/integration.test ./integration && TMPDIR=/scratch /tmp/integration.test -test.run='^TestPhysicalFullDiskPreservesAdmissionAndStopReserve$$' -test.count=1 -hl252-physical-disk-full=true"

deterministic-build:
	rm -rf .cache/build-a .cache/build-b
	mkdir -p .cache/build-a .cache/build-b
	GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-buildid=' -o .cache/build-a/harness-node ./cmd/harness-node
	GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-buildid=' -o .cache/build-a/harness-tool-runner ./cmd/harness-tool-runner
	GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-buildid=' -o .cache/build-b/harness-node ./cmd/harness-node
	GOWORK=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-buildid=' -o .cache/build-b/harness-tool-runner ./cmd/harness-tool-runner
	cmp .cache/build-a/harness-node .cache/build-b/harness-node
	cmp .cache/build-a/harness-tool-runner .cache/build-b/harness-tool-runner

image:
	docker build --pull=false --tag "$(IMAGE)" .

smoke:
	$(PYTHON) scripts/smoke.py "$(IMAGE)"
