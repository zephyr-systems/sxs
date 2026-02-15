package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"

import "config"
import "formatter"
import "../shellx"

VERSION :: "0.1.0"
BUILD_TIME :: "dev"

Output_Format :: enum {
	JSON,
	Text,
	SARIF,
}

Dialect :: enum {
	Auto,
	Bash,
	Zsh,
	Fish,
	Posix,
}

CLI_Options :: struct {
	files: [dynamic]string,
	dialect: Dialect,
	format: Output_Format,
	policy_path: string,
	stdin: bool,
	output_path: string,
	no_builtin: bool,
	block_threshold: string,
	quiet: bool,
	verbose: bool,
	version: bool,
	template: string,
}

print_usage :: proc() {
	fmt.println("SXS (ShellX Scanner) v" + VERSION)
	fmt.println("")
	fmt.println("Usage: sxs [dialect] <file> [options]")
	fmt.println("       sxs rules new [file]")
	fmt.println("       sxs policy new [file]")
	fmt.println("")
	fmt.println("Dialect (optional): bash, zsh, fish, posix (default: auto)")
	fmt.println("")
	fmt.println("Options:")
	fmt.println("  -f, --format         Output format: json, text, sarif (default: json)")
	fmt.println("  -p, --policy         Path to policy file")
	fmt.println("  --stdin              Read from stdin")
	fmt.println("  -o, --output         Output file (default: stdout)")
	fmt.println("  --no-builtin         Disable builtin rules")
	fmt.println("  --block-threshold    Severity to block: Info, Warning, High, Critical")
	fmt.println("  -q, --quiet          Only output findings")
	fmt.println("  -v, --verbose        Verbose output")
	fmt.println("  --version            Show version")
	fmt.println("")
	fmt.println("Examples:")
	fmt.println("  sxs script.sh")
	fmt.println("  sxs bash script.sh")
	fmt.println("  cat script.sh | sxs --stdin")
	fmt.println("  sxs -f sarif script.sh > results.sarif")
	fmt.println("  sxs rules new")
	os.exit(0)
}

parse_options :: proc() -> CLI_Options {
	opts: CLI_Options
	opts.dialect = .Auto
	opts.format = .JSON
	opts.block_threshold = "High"

	args := os.args[1:]
	
	i := 0
	for i < len(args) {
		arg := args[i]
		
		if arg == "rules" && i + 1 < len(args) && args[i + 1] == "new" {
			opts.template = "rules"
			i += 2
			// Capture optional file path
			if i < len(args) && !strings.has_prefix(args[i], "-") {
				append(&opts.files, args[i])
				i += 1
			}
			continue
		}
		if arg == "policy" && i + 1 < len(args) && args[i + 1] == "new" {
			opts.template = "policy"
			i += 2
			// Capture optional file path
			if i < len(args) && !strings.has_prefix(args[i], "-") {
				append(&opts.files, args[i])
				i += 1
			}
			continue
		}
		
		if arg == "--help" || arg == "-h" {
			print_usage()
		}
		if arg == "--version" {
			opts.version = true
			i += 1
			continue
		}
		
		if arg == "--stdin" {
			opts.stdin = true
			i += 1
			continue
		}
		
		if arg == "-f" || arg == "--format" {
			if i + 1 >= len(args) {
				fmt.eprintln("Error: -f/--format requires an argument")
				os.exit(1)
			}
			i += 1
			switch args[i] {
			case "json":
				opts.format = .JSON
			case "text":
				opts.format = .Text
			case "sarif":
				opts.format = .SARIF
			case:
				fmt.eprintln("Error: invalid format, must be json, text, or sarif")
				os.exit(1)
			}
			i += 1
			continue
		}
		
		if arg == "-p" || arg == "--policy" {
			if i + 1 >= len(args) {
				fmt.eprintln("Error: -p/--policy requires an argument")
				os.exit(1)
			}
			i += 1
			opts.policy_path = args[i]
			i += 1
			continue
		}
		
		if arg == "-o" || arg == "--output" {
			if i + 1 >= len(args) {
				fmt.eprintln("Error: -o/--output requires an argument")
				os.exit(1)
			}
			i += 1
			opts.output_path = args[i]
			i += 1
			continue
		}
		
		if arg == "--block-threshold" {
			if i + 1 >= len(args) {
				fmt.eprintln("Error: --block-threshold requires an argument")
				os.exit(1)
			}
			i += 1
			opts.block_threshold = args[i]
			i += 1
			continue
		}
		
		if arg == "--no-builtin" {
			opts.no_builtin = true
			i += 1
			continue
		}
		
		if arg == "-q" || arg == "--quiet" {
			opts.quiet = true
			i += 1
			continue
		}
		
		if arg == "-v" || arg == "--verbose" {
			opts.verbose = true
			i += 1
			continue
		}
		
		if strings.has_prefix(arg, "-") {
			fmt.eprintln("Error: unknown flag:", arg)
			os.exit(1)
		}
		
		append(&opts.files, arg)
		i += 1
	}
	
	if opts.version {
		fmt.println("SXS v" + VERSION)
		fmt.println("Build: " + BUILD_TIME)
		os.exit(0)
	}
	
	if len(opts.files) == 0 && !opts.stdin && opts.template == "" {
		print_usage()
	}
	
	if len(opts.files) > 0 {
		first_file := opts.files[0]
		has_dialect := false
		
		if first_file == "bash" {
			opts.dialect = .Bash
			has_dialect = true
		} else if first_file == "zsh" {
			opts.dialect = .Zsh
			has_dialect = true
		} else if first_file == "fish" {
			opts.dialect = .Fish
			has_dialect = true
		} else if first_file == "posix" {
			opts.dialect = .Posix
			has_dialect = true
		}
		
		if has_dialect {
			for i := 0; i < len(opts.files) - 1; i += 1 {
				opts.files[i] = opts.files[i + 1]
			}
			resize(&opts.files, len(opts.files) - 1)
		}
	}
	
	return opts
}

dialect_to_shellx :: proc(d: Dialect) -> shellx.ShellDialect {
	switch d {
	case .Auto:
		return .Bash
	case .Bash:
		return .Bash
	case .Zsh:
		return .Zsh
	case .Fish:
		return .Fish
	case .Posix:
		return .POSIX
	}
	return .Bash
}

severity_to_shellx :: proc(s: string) -> shellx.FindingSeverity {
	switch s {
	case "Info":
		return .Info
	case "Warning":
		return .Warning
	case "High":
		return .High
	case "Critical":
		return .Critical
	}
	return .High
}

severity_to_string :: proc(s: shellx.FindingSeverity) -> string {
	switch s {
	case .Info:
		return "Info"
	case .Warning:
		return "Warning"
	case .High:
		return "High"
	case .Critical:
		return "Critical"
	}
	return "Info"
}

convert_finding :: proc(f: shellx.SecurityFinding) -> formatter.Finding {
	return formatter.Finding{
		rule_id = strings.clone(f.rule_id),
		severity = severity_to_string(f.severity),
		message = strings.clone(f.message),
		location = formatter.Location{
			file = strings.clone(f.location.file),
			line = f.location.line,
			column = f.location.column,
			length = f.location.length,
		},
		suggestion = strings.clone(f.suggestion),
		phase = strings.clone(f.phase),
		category = strings.clone(f.category),
		confidence = f.confidence,
		matched_text = strings.clone(f.matched_text),
		fingerprint = strings.clone(f.fingerprint),
	}
}

run_scan :: proc(opts: CLI_Options, cfg: config.SXS_Config) -> formatter.Scan_Result {
	result: formatter.Scan_Result
	result.findings = make([dynamic]formatter.Finding, 0, 8)
	result.errors = make([dynamic]string, 0, 4)
	result.success = true
	
	policy := shellx.DEFAULT_SECURITY_SCAN_POLICY
	
	if opts.policy_path != "" {
		p, errs, ok := shellx.load_security_policy_file(opts.policy_path)
		if !ok {
			for err in errs {
				append(&result.errors, err.message)
			}
			result.success = false
			return result
		}
		policy = p
	}
	
	// Apply config settings
	// Note: Config is already merged with CLI for no_builtin and block_threshold
	// via merge_config_with_cli(), so we use opts (merged values)
	
	// Explicitly set use_builtin_rules based on config/CLI
	policy.use_builtin_rules = !opts.no_builtin
	policy.block_threshold = severity_to_shellx(opts.block_threshold)
	
	// Apply config rule_overrides to ShellX policy
	// Allocate slices directly (not dynamic arrays) to avoid lifetime issues
	if len(cfg.rule_overrides) > 0 {
		rule_overrides := make([]shellx.SecurityRuleOverride, len(cfg.rule_overrides))
		
		for override, i in cfg.rule_overrides {
			rule_overrides[i] = shellx.SecurityRuleOverride{
				rule_id = strings.clone(override.rule_id),
				enabled = override.enabled,
				has_severity_override = false,
				severity_override = .Info,
			}
			
			if override.severity_override != "" {
				rule_overrides[i].has_severity_override = true
				rule_overrides[i].severity_override = severity_to_shellx(override.severity_override)
			}
		}
		
		policy.rule_overrides = rule_overrides
	}
	
	// Apply config custom_rules
	if len(cfg.custom_rules) > 0 {
		// Count enabled rules
		enabled_count := 0
		for custom_rule in cfg.custom_rules {
			if custom_rule.enabled {
				enabled_count += 1
			}
		}
		
		if enabled_count > 0 {
			custom_rules := make([]shellx.SecurityScanRule, enabled_count)
			idx := 0
			
			for i := 0; i < len(cfg.custom_rules); i += 1 {
				custom_rule := &cfg.custom_rules[i]
				if !custom_rule.enabled {
					continue
				}
				
				// Convert match_kind string to ShellX enum
				match_kind: shellx.SecurityMatchKind
				switch custom_rule.match_kind {
				case "Substring":
					match_kind = .Substring
				case "Regex":
					match_kind = .Regex
				case "AstCommand":
					match_kind = .AstCommand
				case:
					match_kind = .Substring
				}
				
				// Convert phases array to bit_set
				phases: shellx.SecurityScanPhases
				for phase_str in custom_rule.phases {
					switch phase_str {
					case "Source":
						phases += { .Source }
					case "Translated":
						phases += { .Translated }
					}
				}
				if len(custom_rule.phases) == 0 {
					phases = { .Source }
				}
				
				custom_rules[idx] = shellx.SecurityScanRule{
					rule_id = strings.clone(custom_rule.rule_id),
					enabled = true,
					severity = severity_to_shellx(custom_rule.severity),
					match_kind = match_kind,
					pattern = strings.clone(custom_rule.pattern),
					category = strings.clone(custom_rule.category),
					confidence = custom_rule.confidence,
					phases = phases,
					command_name = strings.clone(custom_rule.command_name),
					arg_pattern = strings.clone(custom_rule.arg_pattern),
					message = strings.clone(custom_rule.message),
					suggestion = strings.clone(custom_rule.suggestion),
				}
				
				idx += 1
			}
			
			policy.custom_rules = custom_rules
		}
	}
	
	// Apply config allowlist_paths and allowlist_commands
	// ShellX policy supports these directly!
	if len(cfg.allowlist_paths) > 0 {
		allowlist_paths := make([dynamic]string, 0, len(cfg.allowlist_paths))
		for path in cfg.allowlist_paths {
			append(&allowlist_paths, strings.clone(path))
		}
		policy.allowlist_paths = allowlist_paths[:]
	}
	
	if len(cfg.allowlist_commands) > 0 {
		allowlist_commands := make([dynamic]string, 0, len(cfg.allowlist_commands))
		for cmd in cfg.allowlist_commands {
			append(&allowlist_commands, strings.clone(cmd))
		}
		policy.allowlist_commands = allowlist_commands[:]
	}
	
	// Apply config ruleset_version if specified
	if cfg.ruleset_version != "" {
		policy.ruleset_version = strings.clone(cfg.ruleset_version)
	}
	
	options := shellx.DEFAULT_SECURITY_SCAN_OPTIONS
	shell_dialect := dialect_to_shellx(opts.dialect)
	
	if opts.stdin {
		data, ok := os.read_entire_file(os.stdin)
		if !ok {
			result.success = false
			append(&result.errors, "Failed to read from stdin")
			return result
		}
		
		if opts.dialect == .Auto {
			shell_dialect = shellx.detect_shell(string(data))
		}
		
		scan_result := shellx.scan_security(string(data), shell_dialect, policy, "<stdin>", options)
		if opts.verbose {
			fmt.eprintln(fmt.aprintf(
				"[sxs] stdin scan policy: builtin=%v custom=%d overrides=%d allow_paths=%d allow_cmds=%d block=%s ruleset=%s dialect=%v",
				policy.use_builtin_rules,
				len(policy.custom_rules),
				len(policy.rule_overrides),
				len(policy.allowlist_paths),
				len(policy.allowlist_commands),
				opts.block_threshold,
				policy.ruleset_version,
				shell_dialect,
			))
		}
		
		for f in scan_result.findings {
			append(&result.findings, convert_finding(f))
		}
		
		result.success = scan_result.success
		result.blocked = scan_result.blocked
		result.ruleset_version = scan_result.ruleset_version
		result.stats = formatter.Scan_Stats{
			files_scanned = 1,
			lines_scanned = scan_result.stats.lines_scanned,
			rules_evaluated = scan_result.stats.rules_evaluated,
			duration_ms = scan_result.stats.duration_ms,
		}
		if opts.verbose {
			fmt.eprintln(fmt.aprintf(
				"[sxs] stdin scan result: success=%v blocked=%v findings=%d lines=%d rules_evaluated=%d ruleset=%s",
				scan_result.success,
				scan_result.blocked,
				len(scan_result.findings),
				scan_result.stats.lines_scanned,
				scan_result.stats.rules_evaluated,
				scan_result.ruleset_version,
			))
		}
		
		shellx.destroy_security_scan_result(&scan_result)
	} else {
		for file in opts.files {
			if !os.exists(file) {
				append(&result.errors, strings.concatenate([]string{"File not found: ", file}))
				continue
			}
			
			if opts.dialect == .Auto {
				data, ok := os.read_entire_file(file)
				if ok {
					shell_dialect = shellx.detect_shell_from_path(file, string(data))
					delete(data)
				}
			}
			
			scan_result := shellx.scan_security_file(file, shell_dialect, policy, options)
			if opts.verbose {
				fmt.eprintln(fmt.aprintf(
					"[sxs] file scan (%s): success=%v blocked=%v findings=%d lines=%d rules_evaluated=%d ruleset=%s builtin=%v",
					file,
					scan_result.success,
					scan_result.blocked,
					len(scan_result.findings),
					scan_result.stats.lines_scanned,
					scan_result.stats.rules_evaluated,
					scan_result.ruleset_version,
					policy.use_builtin_rules,
				))
			}
			
			for f in scan_result.findings {
				append(&result.findings, convert_finding(f))
			}
			
			result.success = result.success && scan_result.success
			if scan_result.blocked {
				result.blocked = true
			}
			
			result.stats.files_scanned += 1
			result.stats.lines_scanned += scan_result.stats.lines_scanned
			result.stats.rules_evaluated += scan_result.stats.rules_evaluated
			result.stats.duration_ms += scan_result.stats.duration_ms
			if result.ruleset_version == "" && scan_result.ruleset_version != "" {
				result.ruleset_version = strings.clone(scan_result.ruleset_version)
			}
			
			shellx.destroy_security_scan_result(&scan_result)
		}
	}
	
	return result
}

merge_config_with_cli :: proc(cfg: config.SXS_Config, cli: CLI_Options) -> CLI_Options {
	merged := cli
	
	// Builtin rules: CLI --no-builtin OR config use_builtin_rules = false
	// If either says disable, disable builtin rules
	if !cfg.use_builtin_rules {
		merged.no_builtin = true
	}
	// CLI --no-builtin already sets no_builtin = true, so this works
	
	// Block threshold: CLI overrides config
	// Only use config if CLI didn't specify (using default "High")
	if cli.block_threshold == "High" && cfg.block_threshold != "" && cfg.block_threshold != "High" {
		merged.block_threshold = cfg.block_threshold
	}
	
	return merged
}

main :: proc() {
	// Load config first
	config_data, config_location := config.find_config()
	cfg := config.SXS_Config{
		use_builtin_rules = true,
		block_threshold = "High",
	}
	if config_data != "" {
		parsed_cfg, ok := config.parse_sxs_config(config_data)
		if ok {
			// Validate config
			valid, err_msg := config.validate_sxs_config(&parsed_cfg)
			if !valid {
				fmt.eprintln("Config validation error:", err_msg)
				os.exit(1)
			}
			cfg = parsed_cfg
		}
	}
	
	// Parse CLI options
	cli_opts := parse_options()
	
	// Merge config with CLI (CLI overrides config)
	opts := merge_config_with_cli(cfg, cli_opts)
	
	if opts.template == "rules" {
		print_rules_template(opts.files[0] if len(opts.files) > 0 else "")
		os.exit(0)
	}
	
	if opts.template == "policy" {
		print_policy_template(opts.files[0] if len(opts.files) > 0 else "")
		os.exit(0)
	}
	
	result := run_scan(opts, cfg)
	
	source := ""
	if len(opts.files) > 0 {
		source = opts.files[0]
	} else if opts.stdin {
		source = "<stdin>"
	}
	
	output: string
	switch opts.format {
	case .JSON:
		output = formatter.format_result_json(result, !opts.quiet)
	case .Text:
		output = formatter.format_result_text(result, opts.verbose, source)
	case .SARIF:
		output = formatter.format_result_sarif(result, source, VERSION)
	}
	
	if opts.output_path != "" {
		os.write_entire_file(opts.output_path, transmute([]u8)output)
	} else {
		fmt.println(output)
	}
	
	if !result.success {
		os.exit(1)
	}
	if result.blocked {
		os.exit(2)
	}
	os.exit(0)
}

print_rules_template :: proc(path: string) {
	content := `{
  "custom_rules": [
    {
      "rule_id": "my.custom.rule",
      "enabled": true,
      "severity": "High",
      "match_kind": "Regex",
      "pattern": "dangerous_pattern",
      "category": "custom",
      "confidence": 0.9,
      "message": "Custom rule matched",
      "suggestion": "Fix the issue",
      "phases": ["source"]
    }
  ]
}
`
	
	output_path := path
	if output_path == "" {
		// Check if running in Zephyr module context
		zephyr_dir := os.get_env("ZEPHYR_SXS_DIR")
		if zephyr_dir != "" {
			output_path = strings.concatenate([]string{zephyr_dir, "/sxs.json"})
		} else {
			output_path = "./sxs.json"
		}
	} else if strings.has_suffix(output_path, "/") {
		output_path = strings.concatenate([]string{output_path, "sxs.json"})
	}
	
	os.write_entire_file(output_path, transmute([]u8)content)
	fmt.println("Created rules template:", output_path)
}

print_policy_template :: proc(path: string) {
	content := `{
  "use_builtin_rules": true,
  "block_threshold": "High",
  "allowlist_paths": [],
  "allowlist_commands": [],
  "rule_overrides": [
    {
      "rule_id": "sec.source_tmp",
      "enabled": true,
      "severity_override": "Warning"
    }
  ],
  "custom_rules": []
}
`
	
	output_path := path
	if output_path == "" {
		// Check if running in Zephyr module context
		zephyr_dir := os.get_env("ZEPHYR_SXS_DIR")
		if zephyr_dir != "" {
			output_path = strings.concatenate([]string{zephyr_dir, "/sxs.json"})
		} else {
			output_path = "./sxs.json"
		}
	} else if strings.has_suffix(output_path, "/") {
		output_path = strings.concatenate([]string{output_path, "sxs.json"})
	}
	
	os.write_entire_file(output_path, transmute([]u8)content)
	fmt.println("Created policy template:", output_path)
}
