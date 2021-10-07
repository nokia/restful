MINIMUM_COVERAGE=85
MAXIMUM_COMPLEXITY=15

RUN:=docker run -it --rm -v $(CURDIR):/src:Z gotools:latest
COV=/tmp/test.out

.PHONY: all
all: gotools
	$(RUN) bash -c ' \
		go get -u ./... && \
		go mod tidy && \
		go vet ./... && \
		go test -race -coverprofile=$(COV) ./... && \
		go list ./... | xargs -L1 golint -set_exit_status && \
		staticcheck ./... && \
		gosec ./... && \
		if [ `gocyclo . | head -n1 | cut -d " " -f1` -gt $(MAXIMUM_COMPLEXITY) ]; then echo Error: Complexity too high; false; fi && \
		if [ `go tool cover -func=$(COV) | tail -n1 | rev | cut -f1 | rev | cut -d. -f1` -lt $(MINIMUM_COVERAGE) ]; then echo "Error: Coverage too low."; false; fi \
	'

.PHONY: gotools
gotools:
	docker build . --tag gotools
