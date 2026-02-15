# SXS Configuration Guide

## Overview

SXS uses a 3-tier configuration system that allows you to customize security rules, set severity levels, and add custom detection rules.

## Configuration Tiers (Priority Order)

1. **Local** (`./sxs.json`) - Project-specific configuration (highest priority)
2. **Module** (`~/.zephyr/modules/sxs/config.json`) - Zephyr module defaults
3. **Global** (`~/.config/sxs/config.json`) - User-wide preferences (lowest priority)

SXS checks each tier in order and uses the first config file found. CLI flags override all config settings.

## Configuration File Format

```json
{
    "use_builtin_rules": true,
    "block_threshold": "High",
    "allowlist_paths": ["vendor", "third_party"],
    "allowlist_commands": ["echo", "printf"],
    "rule_overrides": [...],
    "custom_rules": [...]
}
```

## Configuration Options

### `use_builtin_rules` (boolean)
Enable or disable all built-in security rules.
- Default: `true`
- CLI override: `--no-builtin`

```json
"use_builtin_rules": false
```

### `block_threshold` (string)
Minimum severity level that causes scan to fail (exit code 2).
- Valid values: `"Info"`, `"Warning"`, `"High"`, `"Critical"`
- Default: `"High"`
- CLI override: `--block-threshold`

```json
"block_threshold": "Warning"
```

### `allowlist_paths` (array of strings)
Paths to skip during scanning (relative to project root).

```json
"allowlist_paths": ["vendor", "third_party", "node_modules"]
```

### `allowlist_commands` (array of strings)
Commands to ignore in findings.

```json
"allowlist_commands": ["echo", "printf", "test"]
```

## Rule Overrides

Override built-in rule behavior without modifying the rules themselves.

### Disable a Rule

```json
"rule_overrides": [
    {
        "rule_id": "sec.dangerous_rm",
        "enabled": false
    }
]
```

### Change Rule Severity

```json
"rule_overrides": [
    {
        "rule_id": "sec.overpermissive_chmod",
        "enabled": true,
        "severity_override": "Info"
    }
]
```

### Available Built-in Rules

| Rule ID | Default Severity | Description |
|---------|------------------|-------------|
| `sec.pipe_download_exec` | Critical | Download piped to shell |
| `sec.eval_download` | Critical | Eval with network content |
| `sec.dangerous_rm` | Critical | Destructive rm -rf |
| `sec.overpermissive_chmod` | Warning | chmod 777 |
| `sec.source_tmp` | High | Source from /tmp |
| `sec.ast.eval` | High | AST-detected eval |
| `sec.ast.dynamic_exec` | Critical | Dynamic command substitution |
| `sec.ast.source` | High | Runtime source invocation |
| `sec.ast.pipe_download_exec` | Critical | AST pipe download to shell |
| `sec.ast.shell_dash_c` | High | Shell -c execution |
| `sec.ast.shell_dash_c_dynamic` | Critical | Dynamic -c command |
| `sec.ast.source_process_subst` | Critical | Source process substitution |
| `sec.ast.indirect_exec` | High | Indirect command execution |

## Custom Rules

Add your own security rules to detect patterns specific to your project.

### Custom Rule Structure

```json
"custom_rules": [
    {
        "rule_id": "my.custom.rule",
        "enabled": true,
        "severity": "High",
        "match_kind": "Substring",
        "pattern": "dangerous_pattern",
        "category": "custom",
        "confidence": 0.9,
        "phases": ["Source"],
        "message": "Custom rule matched",
        "suggestion": "Fix the issue"
    }
]
```

### Field Descriptions

- **`rule_id`** (string, required): Unique identifier for the rule (e.g., `"my.custom.hardcoded_password"`)
- **`enabled`** (boolean): Whether the rule is active
- **`severity`** (string): `"Info"`, `"Warning"`, `"High"`, or `"Critical"`
- **`match_kind`** (string): `"Substring"`, `"Regex"`, or `"AstCommand"`
- **`pattern`** (string): Text or regex pattern to match
- **`category`** (string): Rule category (e.g., `"secrets"`, `"execution"`, `"permissions"`)
- **`confidence`** (number): Confidence score 0.0-1.0
- **`phases`** (array): `["Source"]` or `["Translated"]` (AST phases)
- **`message`** (string): Finding message shown to user
- **`suggestion`** (string): Remediation advice
- **`command_name`** (string, optional): For AstCommand rules, the command to match
- **`arg_pattern`** (string, optional): For AstCommand rules, argument pattern

### Example: Hardcoded Password Detection

```json
{
    "rule_id": "custom.hardcoded_password",
    "enabled": true,
    "severity": "High",
    "match_kind": "Substring",
    "pattern": "password=",
    "category": "secrets",
    "confidence": 0.95,
    "phases": ["Source"],
    "message": "Hardcoded password detected",
    "suggestion": "Use environment variables or secret manager"
}
```

### Example: Debug Flag Detection

```json
{
    "rule_id": "custom.debug_flag",
    "enabled": true,
    "severity": "Warning",
    "match_kind": "Regex",
    "pattern": "set -x|set -v",
    "category": "debugging",
    "confidence": 0.8,
    "phases": ["Source"],
    "message": "Debug mode enabled in script",
    "suggestion": "Remove debug flags before production"
}
```

## Template Generation

SXS provides commands to generate configuration templates for quick setup.

### Generate Templates

```bash
# Generate rules template (saves to ./sxs.json by default)
sxs rules new

# Generate policy template (saves to ./sxs.json by default)
sxs policy new

# Save to specific file
sxs rules new my-custom-rules.json
sxs policy new my-custom-policy.json

# Save to directory (appends sxs.json)
sxs rules new ./config/
```

### Context-Aware Template Generation

Template generation is context-aware and adapts based on your environment:

#### Standalone Usage

When running SXS as a standalone tool (installed via brew, apt-get, yum):

```bash
sxs rules new
# Creates: ./sxs.json (in current working directory)
```

#### Zephyr Module Usage

When running SXS as a Zephyr module, templates are saved to the module directory:

```bash
# Zephyr module init.zsh sets ZEPHYR_SXS_DIR
sxs rules new
# Creates: $ZEPHYR_SXS_DIR/sxs.json (module directory)
```

### Environment Variables

#### `ZEPHYR_SXS_DIR`

Set by Zephyr module's `init.zsh` to specify the module directory for SXS configuration.

**For first-party SXS module:**
```bash
export ZEPHYR_SXS_DIR="$HOME/.zephyr/modules/sxs"
```

**For custom module using SXS:**
```bash
export ZEPHYR_SXS_DIR="$HOME/.zephyr/modules/my_custom_module"
```

When `ZEPHYR_SXS_DIR` is set, template generation defaults to that directory:

```bash
# With ZEPHYR_SXS_DIR set
sxs rules new
# Creates: $ZEPHYR_SXS_DIR/sxs.json

# Override with explicit path
sxs rules new /tmp/custom-rules.json
# Creates: /tmp/custom-rules.json (ignores ZEPHYR_SXS_DIR)
```

### Custom Module Development

If you're developing a custom Zephyr module that uses SXS:

1. **Set environment in init.zsh:**
```bash
# ~/.zephyr/modules/my_module/init.zsh
export ZEPHYR_SXS_DIR="$HOME/.zephyr/modules/my_module"
```

2. **Generate templates:**
```bash
sxs rules new
sxs policy new
# Creates sxs.json in your module directory
```

3. **Configure for your module:**
Edit `$ZEPHYR_SXS_DIR/sxs.json` with your module-specific rules and policies.

4. **Use in module scripts:**
```bash
# SXS will auto-load config from ZEPHYR_SXS_DIR
sxs my_module_script.sh
```

## Configuration Examples

### Strict Security Policy

```json
{
    "use_builtin_rules": true,
    "block_threshold": "Warning",
    "rule_overrides": [
        {
            "rule_id": "sec.source_tmp",
            "enabled": true,
            "severity_override": "Critical"
        }
    ]
}
```

### Relaxed Policy with Custom Rules

```json
{
    "use_builtin_rules": true,
    "block_threshold": "Critical",
    "rule_overrides": [
        {
            "rule_id": "sec.overpermissive_chmod",
            "enabled": false
        }
    ],
    "custom_rules": [
        {
            "rule_id": "my.project.specific",
            "enabled": true,
            "severity": "High",
            "match_kind": "Substring",
            "pattern": "TODO_SECURITY",
            "category": "custom",
            "confidence": 1.0,
            "phases": ["Source"],
            "message": "Security TODO found",
            "suggestion": "Address security concern before merge"
        }
    ]
}
```

## CLI Override Examples

CLI flags override all configuration:

```bash
# Override block threshold
sxs --block-threshold Info script.sh

# Disable builtin rules
sxs --no-builtin script.sh

# Use custom policy file
sxs --policy custom-policy.json script.sh

# Combine with config
sxs --block-threshold Warning script.sh  # Uses config, but overrides threshold
```

## Validation

SXS validates configuration on startup:

- Block threshold must be valid severity level
- Rule overrides must reference valid rule IDs
- Custom rules must have required fields
- Custom rule confidence must be 0.0-1.0
- Custom rule match_kind must be valid

Invalid configuration will cause SXS to exit with error message.

## Tips

1. **Start with defaults**: Use built-in rules first, add custom rules as needed
2. **Use local config**: Put `sxs.json` in project root for project-specific rules
3. **Test rules**: Create test scripts to verify custom rules work as expected
4. **Document patterns**: Add comments in config explaining why rules exist
5. **Version control**: Commit `sxs.json` to track security policy changes

## Troubleshooting

### Config not loading
- Check file is valid JSON: `jq . sxs.json`
- Verify file location (local → module → global)
- Check file permissions

### Custom rule not triggering
- Verify pattern matches test case
- Check `enabled: true`
- Confirm `match_kind` is correct
- Test with simpler pattern first

### Validation errors
- Check all required fields are present
- Verify severity values are valid
- Ensure confidence is 0.0-1.0
- Confirm rule_id is unique
## Getting Help

SXS provides comprehensive help through command-line flags with support for both human-readable and machine-readable output formats.

### General Help
```bash
# Text help (default)
sxs --help
sxs -h

# JSON help (machine-readable)
sxs --help --format json
sxs --help -f json
sxs --help --format=json
```

### Subcommand Help
```bash
# Text help
sxs rules new --help
sxs rules new -h
sxs policy new --help
sxs policy new -h

# JSON help
sxs rules new --help --format json
sxs policy new --help --format json
```

### Version Information
```bash
sxs --version
```

### Help Output Formats

- **Text format**: Human-readable output with examples and descriptions
- **JSON format**: Structured machine-readable output for scripting and automation

The JSON help output provides structured data including command information, usage patterns, available options with defaults, and examples. This is useful for programmatic access and integration with other tools.

The help system provides detailed information about commands, options, and examples for using SXS effectively.