MINIMUM_COVERAGE=85
MAXIMUM_COMPLEXITY=15

GO_VER?=latest
RUN:=docker run -it --rm -w $(CURDIR) -v $(CURDIR):$(CURDIR):Z gotools:$(GO_VER)
COV=/tmp/test.out

.PHONY: all
all: gotools
	$(RUN) /usr/bin/make all-go

all-go: test lint

lint:
	go vet ./...
	go list ./... | xargs -L1 golint -set_exit_status
	staticcheck ./...
	gosec ./...
	govulncheck ./...
	gocyclo -over $(MAXIMUM_COMPLEXITY) ./
	@if [ `go tool cover -func=$(COV) | tail -n1 | rev | cut -f1 | rev | cut -d. -f1` -lt $(MINIMUM_COVERAGE) ]; then echo "Error: Coverage too low."; false; fi

test:
	go test -race -coverprofile=$(COV) ./...

.PHONY: gotools
gotools:
	docker pull golang:$(GO_VER) || true # Try to use the latest of the desired Go version
	docker build . --tag gotools
