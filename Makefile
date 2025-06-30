# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -g -I.
LDFLAGS ?=
LDLIBS ?= -luv -lssl -lcrypto

# Target executables
TARGETS = simple_server tls_server

# Source files for the examples
SRC_simple_server = examples/simple_server.c uvhttp.c llhttp.c api.c http.c
SRC_tls_server = examples/tls_server.c uvhttp.c llhttp.c api.c http.c

.PHONY: all clean run-simple run-tls help

all: $(TARGETS)

# Build targets
simple_server: $(SRC_simple_server) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_simple_server) $(LDLIBS)

tls_server: $(SRC_tls_server) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC_tls_server) $(LDLIBS)

# Run servers
run-simple: simple_server
	./simple_server $(ARGS)

run-tls: tls_server
	./tls_server $(ARGS)

# Clean up build artifacts
clean:
	rm -f $(TARGETS)

# Show help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all         Build all server executables (default)"
	@echo "  run-simple  Run the simple HTTP server. Use ARGS to pass arguments (e.g., make run-simple ARGS=8080)"
	@echo "  run-tls     Run the TLS (HTTPS) server. Use ARGS to pass arguments (e.g., make run-tls ARGS=8443)"
	@echo "  clean       Remove build artifacts"
	@echo "  help        Show this help message"
