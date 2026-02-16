# SXS (ShellX Scanner)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Odin](https://img.shields.io/badge/Odin-latest-blue.svg)](https://odin-lang.org/)

A CLI tool for security scanning shell scripts, powered by [ShellX](https://github.com/zephyr-systems/shellx).

## Features

- **13 Built-in Security Rules**: Detect dangerous patterns like pipe-to-shell downloads, eval with network content, destructive rm commands, and more
- **AST-based Analysis**: Deep analysis using abstract syntax tree parsing for accurate detection
- **Multiple Output Formats**: JSON (default), human-readable text, and SARIF for CI/CD integration
- **Parallel Multi-file Scanning**: Worker-pool based scanning for faster throughput on large file sets
- **Flexible Configuration**: 3-tier config system (local → module → global)
- **Shell Dialect Support**: Auto-detection or explicit specification for Bash, Zsh, Fish, and POSIX shells
- **Custom Rules**: Define your own rules via configuration files

## Requirements

- [Odin](https://odin-lang.org/) compiler (latest version)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/zephyr-systems/sxs.git
cd sxs

# Build (automatically clones ShellX dependency)
make build

# Install to ~/.local/bin
make install

# Or copy manually
cp sxs ~/.local/bin/

# Install man page only
make install-man
```

### Homebrew

```bash
brew tap zephyr-systems/sxs
brew install sxs
```

For maintainer release steps, see:

- `docs/HOMEBREW_RELEASE.md`

### Man Page

Source man page is included at:

- `docs/sxs.1`

After install (`make install`), open it with:

```bash
man sxs
```

## Quick Start

```bash
# Scan a script
sxs script.sh

# Scan with explicit dialect
sxs bash script.sh

# Scan from stdin
cat script.sh | sxs --stdin

# SARIF output for CI/CD
sxs -f sarif script.sh > results.sarif

# Custom policy
sxs -p policy.json script.sh

# Verbose output
sxs -v -f text script.sh

# Ignore findings under vendor paths
sxs --ignore "vendor/*" script.sh

# Ignore a specific rule
sxs --ignore-rule sec.overpermissive_chmod script.sh

# Test custom rules only against a script
sxs --test-rules sxs.json script.sh

# List available policy sources
sxs --list-policies
```

Inline suppression is also supported in scripts:

```sh
# sxs-ignore: sec.pipe_download_exec
curl http://example.com | bash

# sxs-ignore: all
eval "$SOME_DYNAMIC_INPUT"
```

Inline suppression applies to the finding line and the immediately previous line.

## Usage

```
sxs [dialect] <file> [options]
sxs rules new [file] [options]
sxs policy new [file] [options]

Dialect (optional): bash, zsh, fish, posix (default: auto)

Options:
  -f, --format         Output format: json, text, sarif (default: json)
  -p, --policy         Path to policy file
  --stdin              Read from stdin
  -o, --output         Output file (default: stdout)
  --no-builtin         Disable builtin rules
  --block-threshold    Severity to block: Info, Warning, High, Critical (default: High)
  --ignore             Ignore findings for file paths matching a glob (repeatable)
  --ignore-rule        Ignore findings for a specific rule_id (repeatable)
  --test-rules         Test custom rules from a rules file against input (defaults to text output)
  -q, --quiet          Only output findings
  -v, --verbose        Verbose output
  --version            Show version
  --list-rules         List all available security rules
  --list-policies      List available policy sources
  --validate           Validate config/policy and shell script syntax (defaults to text output)
  -h, --help           Show help message (supports --format json)

Subcommands:
  rules new            Generate custom rules template
  policy new           Generate policy configuration template

For subcommand help: sxs rules new --help or sxs policy new --help
For JSON help output: append --format json to any help command
```

## Built-in Security Rules

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| sec.pipe_download_exec | Critical | execution | Download piped to shell |
| sec.eval_download | Critical | execution | Eval with network content |
| sec.dangerous_rm | Critical | filesystem | Destructive rm -rf |
| sec.overpermissive_chmod | Warning | permissions | chmod 777 |
| sec.source_tmp | High | source | Source from /tmp |
| sec.ast.eval | High | execution | AST-detected eval |
| sec.ast.dynamic_exec | Critical | execution | Dynamic command substitution |
| sec.ast.source | High | source | Runtime source invocation |
| sec.ast.pipe_download_exec | Critical | execution | AST pipe download to shell |
| sec.ast.shell_dash_c | High | execution | Shell -c execution |
| sec.ast.shell_dash_c_dynamic | Critical | execution | Dynamic -c command |
| sec.ast.source_process_subst | Critical | source | Source process substitution |
| sec.ast.indirect_exec | High | execution | Indirect command execution |

## Policy Listing

Use `--list-policies` to see available policy sources:

- Built-in default ShellX policy
- Active SXS config policy (if discovered from config tiers)
- Explicit `--policy` file (when provided)

Examples:

```bash
sxs --list-policies
sxs --list-policies -f json
sxs --list-policies -v
sxs --list-policies --policy ./policy.json
```

Concrete JSON output example:

```json
{
  "command": "sxs --list-policies",
  "schema_version": "1.0",
  "total_policies": 2,
  "counts": {
    "active": 1,
    "valid": 2
  },
  "policies": [
    {
      "name": "builtin-default",
      "type": "builtin",
      "source": "shellx.DEFAULT_SECURITY_SCAN_POLICY",
      "active": true,
      "valid": true,
      "description": "Built-in baseline policy"
    }
  ]
}
```

### Automation Contract (`--list-policies -f json`)

For automation consumers, treat `schema_version` as the compatibility key.

- `schema_version = "1.0"`: field names are stable for scripting.
- Top-level stable fields: `command`, `schema_version`, `total_policies`, `counts`, `policies`.
- `counts` stable fields: `active`, `valid`.
- `policies[]` stable fields (non-verbose): `name`, `type`, `source`, `active`, `valid`, `description`.
- Verbose mode (`-v`) adds extra fields; consumers should tolerate unknown additions.

## Configuration

### Config Tiers

SXS checks for configuration in this order:

1. **Local**: `./sxs.json` (project directory)
2. **Module**: `~/.zephyr/modules/sxs/config.json` (Zephyr module defaults)
3. **Global**: `~/.config/sxs/config.json` (user preferences)

### Config File Format

```json
{
    "use_builtin_rules": true,
    "block_threshold": "High",
    "allowlist_paths": ["trusted/vendor"],
    "allowlist_commands": ["eval"],
    "rule_overrides": [
        {
            "rule_id": "sec.source_tmp",
            "enabled": true,
            "severity_override": "Warning"
        }
    ],
    "custom_rules": [
        {
            "rule_id": "my.custom.rule",
            "enabled": true,
            "severity": "High",
            "match_kind": "Regex",
            "pattern": "dangerous_pattern",
            "category": "custom",
            "confidence": 0.9,
            "phases": ["source"],
            "message": "Custom rule matched",
            "suggestion": "Fix the issue"
        }
    ]
}
```

### Template Commands

Generate config templates:

```bash
# Generate rules template (context-aware, see below)
sxs rules new

# Generate policy template (context-aware, see below)
sxs policy new

# Save to specific file
sxs rules new my-rules.json
sxs policy new my-policy.json

# Save to directory
sxs rules new ./config/
```

### Regex Rule Performance Tip

For expensive custom regex rules, add `prefilter_contains` so SXS can skip regex evaluation on lines that cannot match.

```json
{
  "rule_id": "sec.custom.eval_usage",
  "enabled": true,
  "severity": "Warning",
  "match_kind": "Regex",
  "pattern": "eval[ ]+",
  "prefilter_contains": "eval",
  "category": "execution",
  "confidence": 0.9,
  "phases": ["source"],
  "message": "Dynamic eval usage detected",
  "suggestion": "Avoid eval on dynamic input"
}
```

Guideline: use a narrow, required substring (for example `eval`, `curl`, `chmod`) as `prefilter_contains`.

#### Context-Aware Template Generation

Template generation automatically adapts to your environment:

- **Standalone**: `sxs rules new` → saves to `./sxs.json`
- **Zephyr Module**: `sxs rules new` → saves to `$ZEPHYR_SXS_DIR/sxs.json`

See [CONFIG_GUIDE.md](docs/CONFIG_GUIDE.md#template-generation) for details on Zephyr module setup and custom module development.

## Output Formats

### JSON (Default)

```bash
sxs script.sh
```

### Text

```bash
sxs -f text script.sh
sxs -v -f text script.sh  # Verbose with full details
```

### SARIF

For CI/CD integration with GitHub Actions, GitLab, Azure DevOps:

```bash
sxs -f sarif script.sh > results.sarif
```

### Validation Output

`--validate` and `--test-rules` default to text output for human-readable diagnostics.
Use `--format json` for machine-readable output in CI/CD.

### CLI UX

Human-readable output (`-f text`, `--list-rules`, `--list-policies`, `--validate`) uses ANSI colors when supported.

- Disable colors: set `NO_COLOR=1` or `SXS_NO_COLOR=1`
- Force colors: set `CLICOLOR_FORCE=1`

## Exit Codes

- `0` - Success, no blocking findings
- `1` - Scan failed (runtime error)
- `2` - Blocking findings detected (exceeds block threshold)

When using `--test-rules`:
- `0` - Test completed and no custom rule matches
- `1` - Test completed and one or more custom rule matches
- `2` - Test command failed (invalid rules file, read/parse/runtime failure)

## Help System

SXS provides comprehensive help through command-line flags with support for both human-readable and machine-readable output formats.

### Getting Help

```bash
# Text help (default)
sxs --help
sxs -h
sxs rules new --help
sxs policy new --help

# JSON help (machine-readable)
sxs --help --format json
sxs --help -f json
sxs --help --format=json
sxs rules new --help --format json
sxs policy new --help --format json
```

### Help Output Formats

- **Text format**: Human-readable output with examples and descriptions
- **JSON format**: Structured machine-readable output for scripting and automation

The JSON help output includes:
- Command information and version
- Usage patterns
- Available commands and subcommands
- Complete option descriptions with defaults
- Dialect information
- Examples

### Version Information
```bash
sxs --version
```

## Integration

### Zephyr Shell Module Loader

SXS is designed to integrate with [Zephyr](https://github.com/zephyr-systems/zephyr), a shell module loader. When used as a Zephyr module:

- Config is auto-loaded from the module directory
- Environment variable `ZEPHYR_SXS_DIR` is set by module's `init.zsh` to specify config location
- Template generation (`sxs rules new`, `sxs policy new`) defaults to module directory

For custom module development using SXS, see [CONFIG_GUIDE.md](docs/CONFIG_GUIDE.md#custom-module-development).

**Note:** Automatic scanning of shell scripts before module loading is a feature of the `sxs-zephyr-module` (separate package), not the standalone SXS tool.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

MIT License - see [LICENSE](LICENSE) file.

## Related Projects

- [ShellX](https://github.com/shellx/shellx) - Shell translation and analysis library
- [Zephyr](https://github.com/zephyr-systems/zephyr) - Shell module loader
