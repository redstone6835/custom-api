# Custom-API customs gateway: build and verification entry points.
#
# Everything routes through deploy/scripts/deploy.sh so that the Makefile and
# the shell tooling cannot drift apart.

SHELL := /bin/sh
DEPLOY := ./deploy/scripts/deploy.sh
VERSION := $(shell sed -n 's/.*Version *= *"\([^"]*\)".*/\1/p' src/customapi/internal/version/version.go | head -1)

.PHONY: help all build stage ship install test clean fmt vet test-race test-cover \
        local-test vm vm-baseline vm-status vm-console vm-stop vm-destroy smoke intel e2e

# help prints the target map. The text lives in docs/MAKE-HELP.txt so that it
# cannot be mangled by shell or make quoting rules.
help:
	@cat docs/MAKE-HELP.txt

# --- build and deploy -------------------------------------------------------

all: build stage ship install test

build:
	@$(DEPLOY) build

stage:
	@$(DEPLOY) stage

ship:
	@$(DEPLOY) ship

install:
	@$(DEPLOY) install

test:
	@$(DEPLOY) test

# --- verification -----------------------------------------------------------

local-test:
	@$(DEPLOY) local-test

fmt:
	@cd src/customapi && gofmt -w . && echo "formatted"
	@cd src/customapi && test -z "$$(gofmt -l .)" && echo "gofmt clean"

vet:
	@cd src/customapi && go vet ./... && echo "vet clean"

test-race:
	@cd src/customapi && go test ./... -race -count=1

test-cover:
	@cd src/customapi && go test ./internal/... -cover -count=1

smoke:
	@ssh $${CUSTOMAPI_TARGET:-customapi-bsd} \
		'sudo -n sh /usr/local/share/customapi/smoke-test.sh'

intel:
	@ssh $${CUSTOMAPI_TARGET:-customapi-bsd} \
		'sudo -n sh /usr/local/share/customapi/intel-test.sh'

e2e: smoke intel

# --- test virtual machine ---------------------------------------------------

vm:
	@./vm/create-vm.sh

vm-baseline:
	@./vm/create-vm.sh baseline

vm-status:
	@./vm/create-vm.sh status

vm-console:
	@./vm/create-vm.sh console

vm-stop:
	@./vm/create-vm.sh stop

vm-destroy:
	@./vm/create-vm.sh destroy

# --- housekeeping -----------------------------------------------------------

clean:
	@$(DEPLOY) clean
	@rm -rf dist
	@echo "cleaned"
