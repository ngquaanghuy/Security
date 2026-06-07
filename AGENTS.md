# Security - C++ CLI Security Tool

## Build & Test
```bash
# Build (Ninja)
cmake -G Ninja -B build && ninja -C build

# Run all tests
ninja -C build test

# Run single test
./build/test_encoders
./build/test_chacha20
```

## Project Structure
- `src/main.cpp` - CLI entry point (encryption/encoding tool)
- `src/encoders/` - Base64, Base85, Base32, Base36 encoding
- `src/crypto/` - ChaCha20 encryption + key management (OpenSSL)
- `include/` - Public headers
- `test/` - Unit tests (test_encoders, test_chacha20)

## Key Conventions
- C++17, CMake 3.10+, requires OpenSSL
- Version in `include/version.h` (PROJECT_NAME, PROJECT_VERSION)
- No lint/formatter configured - follow existing code style
- Self-executing wrapper scripts generated for output files (Python + OpenSSL)

## CLI Usage
```
Security [OPTIONS] <input>
  -a, --algorithm <name>   Algorithm: base64|base85|base32|base36|chacha20 (default: base64)
  -f, --file               Treat input as file path
  -o, --output <file>      Write output to file (creates self-executing wrapper)
  -d, --decrypt            Decrypt (chacha20 only)
  --keygen [algo]          Generate key (default)
  --keyenv                 Read key from KEYENV env var
  --keyfile [path]         Read key from file (raw or hex)
```

## Testing
- Tests use CTest via `enable_testing()` in CMakeLists.txt
- Two test executables: `test_encoders`, `test_chacha20`
- No test framework - plain C++ asserts

# GLOBAL RULES

## Architecture and code structure
- Prioritize simplicity and readability. Split complex functions into smaller ones that each perform only a single responsibility
- Modify only the code and shell commands relevant to the current task. Avoid changing unrelated parts of the codebase or environment

## Code Style
- Comment important logic and implementation details when necessary. Use English exclusively for all comments
- Prefer functional programming over object-oriented programming whenever practical
- Declare all import statements at the top of the file and avoid placing imports inside functions or conditional blocks unless necessary
- Favor modern, idiomatic code over legacy C-style approaches
- Before implementing new code, verify whether the required logic, functionality, or library already exists and can be reused

## Error Handling
- Always report errors clearly and explicitly. Never fail silently or ignore errors
- Identify and explain the root cause of errors, not just their symptoms.
- Focus on resolving the underlying cause of a problem. Avoid patches that only mask symptoms without eliminating the source of the issue
- Never stop at identifying the problem. Follow the full remediation cycle until the issue is verified as resolved: Error → Root Cause Analysis → Fix → Build → Test → Pass


## Testing
- Do not rely on a single successful test run. Execute 10–15 consecutive test runs and only accept the fix if all runs pass consistently
- Maintain a clean project structure by keeping all test-related files in the /tests/ directory and separating them from source, root, and build artifacts

## Termianl Usage
- Treat the repository as read-only. Never perform Git write operations (git add, git commit, git push, git merge, git rebase, git reset, etc.). Only use Git commands that inspect or retrieve information without altering repository state
- External dependencies, documentation, and reference materials may be downloaded using curl or wget when necessary. Prefer official and trusted sources whenever possible

## Effective
- Ensure the code maintains a balanced trade-off between performance, speed, security, readability, and maintainability
- Reasonable performance degradation (up to 2–3×) may be accepted in exchange for stronger security guarantees. However, such trade-offs must be intentional, justified, and kept within controllable limits


## Mandatory Regulations
- Compliance with the entire #GLOBAL RULES section of AGENTS.md is required. No rule may be ignored, bypassed, or selectively applied