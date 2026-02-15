# SXS (ShellX Scanner)

A CLI tool for security scanning shell scripts, powered by [ShellX](https://github.com/shellx/shellx).

## Features

- **13 Built-in Security Rules**: Detect dangerous patterns like pipe-to-shell downloads, eval with network content, destructive rm commands, and more
- **AST-based Analysis**: Deep analysis using abstract syntax tree parsing for accurate detection
- **Multiple Output Formats**: JSON (default), human-readable text, and SARIF for CI/CD integration
- **Flexible Configuration**: 3-tier config system (local → module → global)
- **Shell Dialect Support**: Auto-detection or explicit specification for Bash, Zsh, Fish, and POSIX shells
- **Custom Rules**: Define your own rules via configuration files

## Requirements

- [Odin](https://odin-lang.org/) compiler (latest version)
- [ShellX](https://github.com/shellx/shellx) (included as dependency)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/zephyr-systems/sxs.git
cd sxs

# Build
make build

# Install to ~/.local/bin
make install

# Or copy manually
cp sxs ~/.local/bin/
```

### Homebrew (Coming Soon)

```bash
brew install zephyr-systems/sxs/sxs
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
```

## Usage

```
sxs [dialect] <file> [options]

Dialect (optional): bash, zsh, fish, posix (default: auto)

Options:
  -f, --format         Output format: json, text, sarif (default: json)
  -p, --policy         Path to policy file
  --stdin              Read from stdin
  -o, --output         Output file (default: stdout)
  --no-builtin         Disable builtin rules
  --block-threshold    Severity to block: Info, Warning, High, Critical
  -q, --quiet          Only output findings
  -v, --verbose        Verbose output
  --version            Show version
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
# Generate rules template
sxs rules new

# Generate policy template
sxs policy new

# Save to file
sxs rules new my-rules.json
sxs policy new my-policy.json
```

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

## Exit Codes

- `0` - Success, no blocking findings
- `1` - Scan failed (runtime error)
- `2` - Blocking findings detected (exceeds block threshold)

## Integration

### Zephyr Shell Module Loader

SXS is designed to integrate with [Zephyr](https://github.com/zephyr-systems/zephyr), a shell module loader. When used as a Zephyr module:

- Config is auto-loaded from the module directory
- Environment variable `ZEPHYR_CURRENT_MODULE` is checked for module-specific rules
- Shell scripts in modules are automatically scanned before loading

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

MIT License - see [LICENSE](LICENSE) file.

## Related Projects

- [ShellX](https://github.com/shellx/shellx) - Shell translation and analysis library
- [Zephyr](https://github.com/zephyr-systems/zephyr) - Shell module loader
