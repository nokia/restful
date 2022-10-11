MINIMUM_COVERAGE=85
MAXIMUM_COMPLEXITY=15

RUN:=docker run -it --rm -w $(CURDIR) -v $(CURDIR):$(CURDIR):Z gotools:latest
COV=/tmp/test.out

.PHONY: all
all: gotools
	$(RUN) /usr/bin/make all-go

all-go:
	go get -u ./...
	go mod tidy
	go vet ./...
	go test -race -coverprofile=$(COV) ./...
	go list ./... | xargs -L1 golint -set_exit_status
	staticcheck ./...
	gosec ./...
	govulncheck ./...
	gocyclo -over $(MAXIMUM_COMPLEXITY) ./
	@if [ `go tool cover -func=$(COV) | tail -n1 | rev | cut -f1 | rev | cut -d. -f1` -lt $(MINIMUM_COVERAGE) ]; then echo "Error: Coverage too low."; false; fi

.PHONY: gotools
gotools:
	docker pull golang:latest # Make sure latest is latest
	docker build . --tag gotools
