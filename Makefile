SHELL := /bin/bash

PROFILE ?= release
SERVER := target/$(PROFILE)/quicmonoio
CLIENT := target/$(PROFILE)/examples/quic_client

.PHONY: all build run client test clean

all: build

## build: compile server and client (PROFILE=release by default)
build:
	cargo build --profile $(PROFILE) --bins --examples

## run: start the server (HTTP :8080, QUIC :4433)
run: build
	$(SERVER)

## client: send a message to a running server over QUIC (MSG="...")
client: build
	$(CLIENT) $(MSG)

## test: cargo tests + end-to-end check (HTTP and QUIC) against a fresh server
test: build
	cargo test --profile $(PROFILE)
	@set -e; \
	$(SERVER) > /dev/null 2>&1 & pid=$$!; \
	trap 'kill $$pid 2>/dev/null' EXIT; \
	for i in $$(seq 1 50); do \
		curl -sf http://127.0.0.1:8080/health > /dev/null && break; sleep 0.1; \
	done; \
	echo "--> HTTP /";       curl -sf http://127.0.0.1:8080/ > /dev/null; \
	echo "--> HTTP /health"; curl -sf http://127.0.0.1:8080/health; echo; \
	echo "--> QUIC echo";    $(CLIENT) "make test"; \
	echo "All checks passed."

## clean: remove build artifacts and the generated cert
clean:
	cargo clean
	rm -f .test-cert.der
