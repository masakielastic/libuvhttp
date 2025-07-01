# Project: libuvhttp

This document provides context and guidelines for the AI assistant working on the `libuvhttp` project.

## Project Overview

`libuvhttp` is a simple, high-performance HTTP/1.1 server library built using `libuv` and `llhttp`. It is designed as a single-header library for ease of integration and supports TLS via OpenSSL.

A key feature of this library is its **zero-copy parsing** mechanism for request headers, which minimizes memory allocations and data copying to achieve high performance.

### Core Design Constraint: Single-Threaded Operation

A fundamental design principle of this project is that it is intended for **single-threaded environments**, primarily for use cases like PHP extensions. The library is **not thread-safe**. All operations related to the server, requests, and responses must be performed on the same thread that runs the `libuv` event loop. This constraint must be respected in all future development and code modifications.

## Technical Background

### Core Components
*   **`uvhttp.h`**: The main single-header library containing both the public API and the implementation.
*   **`libuv`**: Used for asynchronous network I/O.
*   **`llhttp`**: Used for parsing HTTP/1.1 messages.
*   **`OpenSSL`**: Used for TLS (HTTPS) support.

### llhttp-derived Code
The files `api.c`, `http.c`, `llhttp.c`, and `llhttp.h` are derived from the `llhttp` parser project. They are part of the core parsing engine and should generally not be modified unless there is a specific need to patch the parser itself. The main integration logic is within `uvhttp.h`.

## Development Guidelines

### Commit Messages: Conventional Commits

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification. All commit messages must adhere to this format.

**Format:**
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Allowed `type` values:**
*   **feat**: A new feature
*   **fix**: A bug fix
*   **docs**: Documentation only changes
*   **style**: Changes that do not affect the meaning of the code (white-space, formatting, etc.)
*   **refactor**: A code change that neither fixes a bug nor adds a feature
*   **perf**: A code change that improves performance
*   **test**: Adding missing tests or correcting existing tests
*   **build**: Changes that affect the build system or external dependencies
*   **ci**: Changes to our CI configuration files and scripts
*   **chore**: Other changes that don't modify src or test files
*   **revert**: Reverts a previous commit

### Co-authoring
When creating git commits, always add the following `Co-authored-by` line to the commit message:
`Co-authored-by: Gemini <gemini-cli@google.com>`