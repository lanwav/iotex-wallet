########################################################################################################################
# Copyright (c) 2018 IoTeX
# This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
# warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
# permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
# License 2.0 that can be found in the LICENSE file.
########################################################################################################################

# Go parameters
GOCMD=go
GOLINT=golint
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BUILD_TARGET_SERVER=server
SKIP_DEP=false

# Pkgs
ALL_PKGS := $(shell go list ./... )
PKGS := $(shell go list ./... | grep -v /test/ )
ROOT_PKG := "github.com/iotexproject/iotex-wallet"

# Docker parameters
DOCKERCMD=docker

TEST_IGNORE= ".git,vendor"
COV_OUT := profile.coverprofile
COV_REPORT := overalls.coverprofile
COV_HTML := coverage.html

LINT_LOG := lint.log

V ?= 0
ifeq ($(V),0)
	ECHO_V = @
else
	VERBOSITY_FLAG = -v
	DEBUG_FLAG = -debug
endif

all: clean build test
.PHONY: build
build:
	$(GOBUILD) -o ./bin/$(BUILD_TARGET_SERVER) -v ./$(BUILD_TARGET_SERVER)

.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

.PHONY: lint
lint:
	go list ./... | grep -v /vendor/ | xargs $(GOLINT)

.PHONY: lint-rich
lint-rich:
	$(ECHO_V)rm -rf $(LINT_LOG)
	@echo "Running golangcli lint..."
	$(ECHO_V)golangci-lint run $(VERBOSITY_FLAG)--enable-all | tee -a $(LINT_LOG)

.PHONY: test
test: fmt
	$(GOTEST) -short ./...

.PHONY: test-rich
test-rich:
	@echo "Running test cases..."
	$(ECHO_V)rm -f $(COV_REPORT)
	$(ECHO_V)touch $(COV_OUT)
	$(ECHO_V)RICHGO_FORCE_COLOR=1 overalls \
		-project=$(ROOT_PKG) \
		-go-binary=richgo \
		-ignore $(TEST_IGNORE) \
		$(DEBUG_FLAG) -- \
		$(VERBOSITY_FLAG) -short | \
		grep -v -e "Test args" -e "Processing"

.PHONY: test-html
test-html: test-rich
	@echo "Generating test report html..."
	$(ECHO_V)gocov convert $(COV_REPORT) | gocov-html > $(COV_HTML)
	$(ECHO_V)open $(COV_HTML)

.PHONY: dev-deps
dev-deps:
	@echo "Installing dev dependencies..."
	$(ECHO_V)go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	$(ECHO_V)go get -u github.com/kyoh86/richgo
	$(ECHO_V)go get -u github.com/axw/gocov/gocov
	$(ECHO_V)go get -u gopkg.in/matm/v1/gocov-html
	$(ECHO_V)go get -u github.com/go-playground/overalls

.PHONY: clean
clean:
	@echo "Cleaning..."
	$(ECHO_V)rm -f ./bin/$(BUILD_TARGET_SERVER)
	$(ECHO_V)rm -f $(COV_REPORT) $(COV_HTML) $(LINT_LOG)
	$(ECHO_V)find . -name $(COV_OUT) -delete
	$(ECHO_V)find . -name $(TESTBED_COV_OUT) -delete
	$(ECHO_V)$(GOCLEAN) -i $(PKGS)

.PHONY: run
run:
	$(GOBUILD) -o ./bin/$(BUILD_TARGET_SERVER) -v ./$(BUILD_TARGET_SERVER)
	./bin/$(BUILD_TARGET_SERVER)

.PHONY: docker
docker:
	$(DOCKERCMD) build -t $(USER)/iotex-wallet-go:latest --build-arg SKIP_DEP=$(SKIP_DEP) .