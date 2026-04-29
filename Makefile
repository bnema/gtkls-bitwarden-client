.PHONY: test race lint safety check

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

safety:
	@if grep -RInE --exclude=Makefile --exclude='*_test.go' --exclude-dir=.git 'DumpRequest|DumpResponse|httputil|access_token|refresh_token|password=' .; then \
		echo "unsafe secret/body-dump pattern found"; \
		exit 1; \
	fi
	@if [ -d internal ] && grep -RInE --exclude='*_test.go' 'os\.WriteFile|CreateTemp' internal; then \
		echo "unexpected disk persistence pattern found"; \
		exit 1; \
	fi
	@if [ -d internal ] && grep -RInE --exclude='*_test.go' 'MkdirAll' internal | grep -v 'internal/adapters/cache/file/store.go' | grep -v 'internal/adapters/cache/file/outbox_store.go' | grep -v 'internal/adapters/config/viper/manager.go'; then \
		echo "unexpected directory creation outside cache/config adapters"; \
		exit 1; \
	fi

check: test lint safety
