# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -g -I.
LDFLAGS ?=
LDLIBS ?= -luv -lssl -lcrypto

# Target executable
TARGET = simple_server

# Source file for the example
SRC = examples/simple_server.c uvhttp.c llhttp.c api.c http.c

.PHONY: all clean run

all: $(TARGET)

# Build the target executable
$(TARGET): $(SRC) uvhttp.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LDLIBS)

# Run the server
run: all
	./$(TARGET)

# Clean up build artifacts
clean:
	rm -f $(TARGET)
