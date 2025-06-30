# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -g -I.
LDFLAGS ?=
LDLIBS ?= -luv -lssl -lcrypto

# Target executable
TARGET = simple_server

# Source file for the example
SRC = examples/simple_server.c uvhttp.c llhttp.c api.c http.c

.PHONY: all clean run help

all: $(TARGET)

# Build the target executable
$(TARGET): $(SRC) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LDLIBS)

# Run the server
run: all
	./$(TARGET) $(ARGS)

# Clean up build artifacts
clean:
	rm -f $(TARGET)

# Show help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all       Build the server executable (default)"
	@echo "  run       Run the server. Use ARGS to pass arguments (e.g., make run ARGS=8888)"
	@echo "  clean     Remove build artifacts"
	@echo "  help      Show this help message"
