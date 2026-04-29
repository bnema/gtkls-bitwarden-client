.PHONY: test race lint safety check

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run ./...

safety:
	@if grep -RInE --exclude=Makefile --exclude-dir=.git 'DumpRequest|DumpResponse|httputil|access_token|refresh_token|password=' .; then \
		echo "unsafe secret/body-dump pattern found"; \
		exit 1; \
	fi
	@if [ -d internal ] && grep -RInE 'os\.WriteFile|MkdirAll|CreateTemp' internal; then \
		echo "unexpected disk persistence pattern found"; \
		exit 1; \
	fi

check: test lint safety
