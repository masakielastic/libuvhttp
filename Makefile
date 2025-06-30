# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -g -I.
LDFLAGS ?=
LDLIBS ?= -luv -lssl -lcrypto

# Target executables
TARGETS = simple_server tls_server chunked_server

# Source files for the examples
SRC_simple_server = examples/simple_server.c uvhttp.c llhttp.c api.c http.c
SRC_tls_server = examples/tls_server.c uvhttp.c llhttp.c api.c http.c
SRC_chunked_server = examples/chunked_server.c uvhttp.c llhttp.c api.c http.c

# Certificate files
CERT_FILE = cert.pem
KEY_FILE = key.pem

# Test executable
TEST_TARGET = run_tests
TEST_SRC = tests/test_main.c uvhttp.c llhttp.c api.c http.c

.PHONY: all clean run-simple run-tls run-chunked test help certs

all: $(TARGETS)

# Build targets
simple_server: $(SRC_simple_server) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_simple_server) $(LDLIBS)

tls_server: $(SRC_tls_server) uvhttp.h certs
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_tls_server) $(LDLIBS)

chunked_server: $(SRC_chunked_server) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_chunked_server) $(LDLIBS)

# Run servers
run-simple: simple_server
	./simple_server $(ARGS)

run-tls: tls_server
	./tls_server $(ARGS)

run-chunked: chunked_server
	./chunked_server $(ARGS)

# Build and run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRC) certs
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(LDLIBS)

# Generate self-signed certificates if they don't exist
certs: $(CERT_FILE)

$(CERT_FILE):
	@echo "Generating self-signed certificate..."
	@openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout $(KEY_FILE) -out $(CERT_FILE) -days 365 \
		-subj "/C=XX/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

# Clean up build artifacts
clean:
	rm -f $(TARGETS) $(TEST_TARGET) $(CERT_FILE) $(KEY_FILE)

# Show help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all         Build all server executables (default)"
	@echo "  run-simple  Run the simple HTTP server. Use ARGS to pass arguments (e.g., make run-simple ARGS=8080)"
	@echo "  run-tls     Run the TLS (HTTPS) server. Use ARGS to pass arguments (e.g., make run-tls ARGS=8443)"
	@echo "  run-chunked Run the chunked response server"
	@echo "  test        Build and run the tests"
	@echo "  certs       Generate self-signed certificates"
	@echo "  clean       Remove build artifacts and certificates"
	@echo "  help        Show this help message"
