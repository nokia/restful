# Copyright 2021-2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

FROM golang:latest

RUN go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/lint/golint@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest && \
	go install github.com/fzipp/gocyclo/cmd/gocyclo@latest && \
	#go install golang.org/x/vuln/cmd/govulncheck@latest \
	go install github.com/google/osv-scanner/cmd/osv-scanner@latest
