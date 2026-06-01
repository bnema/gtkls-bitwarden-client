APP := gtkls-bitwarden-client
CMD := ./cmd/$(APP)
DIST_DIR := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test race lint safety check install build

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

EXCLUDE_DISK_HELPERS := internal/adapters/fileutil/atomic.go internal/adapters/gui/omnibox/type_icons_linux.go internal/adapters/logging/zerowrap.go
GREP_EXCLUDE := $(foreach p,$(EXCLUDE_DISK_HELPERS),| grep -v '$(p)')

safety:
	@if grep -RInE --exclude=Makefile --exclude='*_test.go' --exclude-dir=.git 'DumpRequest|DumpResponse|httputil|access_token|refresh_token|password=' . | grep -v 'refresh_token_bundle'; then \
		echo "unsafe secret/body-dump pattern found"; \
		exit 1; \
	fi
	@if [ -d internal ] && grep -RInE --exclude='*_test.go' 'os\.WriteFile|CreateTemp' internal $(GREP_EXCLUDE); then \
		echo "unexpected disk persistence pattern found"; \
		exit 1; \
	fi
	@if [ -d internal ] && grep -RInE --exclude='*_test.go' 'MkdirAll' internal $(GREP_EXCLUDE); then \
		echo "unexpected directory creation outside cache/config adapters"; \
		exit 1; \
	fi

install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

build:
	mkdir -p $(DIST_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP) $(CMD)
	git rev-parse HEAD > $(DIST_DIR)/git-head.txt
	git show-ref --tags -d > $(DIST_DIR)/git-tags.txt || true

check: test lint safety
