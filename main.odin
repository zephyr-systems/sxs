package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:path/filepath"
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
	list_rules: bool,
	validate: bool,
	ignore_patterns: [dynamic]string,
	template: string,
}

print_usage :: proc() {
	fmt.println("SXS (ShellX Scanner) v" + VERSION)
	fmt.println("")
	fmt.println("Usage: sxs [dialect] <file> [options]")
	fmt.println("       sxs rules new [file]")
	fmt.println("       sxs policy new [file]")
	fmt.println("")
	fmt.println("Commands:")
	fmt.println("  rules new [file]     Generate custom rules template")
	fmt.println("  policy new [file]    Generate policy configuration template")
	fmt.println("")
	fmt.println("Dialect (optional): bash, zsh, fish, posix (default: auto)")
	fmt.println("")
	fmt.println("Options:")
	fmt.println("  -f, --format         Output format: json, text, sarif (default: json)")
	fmt.println("  -p, --policy         Path to policy file")
	fmt.println("  --stdin              Read from stdin")
	fmt.println("  -o, --output         Output file (default: stdout)")
	fmt.println("  --no-builtin         Disable builtin rules")
	fmt.println("  --block-threshold    Severity to block: Info, Warning, High, Critical (default: High)")
	fmt.println("  -q, --quiet          Only output findings")
	fmt.println("  -v, --verbose        Verbose output")
	fmt.println("  --version            Show version")
	fmt.println("  --list-rules         List all available security rules")
	fmt.println("  --validate           Validate config/policy and shell script syntax")
	fmt.println("  --ignore             Ignore findings for file paths matching a glob (repeatable)")
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println("Examples:")
	fmt.println("  sxs script.sh")
	fmt.println("  sxs bash script.sh")
	fmt.println("  cat script.sh | sxs --stdin")
	fmt.println("  sxs -f sarif script.sh > results.sarif")
	fmt.println("  sxs rules new")
	fmt.println("  sxs rules new --help")
	fmt.println("  sxs policy new --help")
	fmt.println("  sxs --validate script.sh")
	fmt.println("  sxs --ignore 'vendor/*' script.sh")
	os.exit(0)
}

print_rules_new_help :: proc(args: []string, arg_index: int) {
	// Check if format is specified
	if arg_index < len(args) {
		next_arg := args[arg_index]
		// Handle --format json
		if next_arg == "-f" || next_arg == "--format" {
			if arg_index + 1 < len(args) {
				format_arg := args[arg_index + 1]
				if format_arg == "json" {
					print_rules_new_json()
					os.exit(0)
				}
			}
		}
		// Handle --format=json (with equals)
		if strings.has_prefix(next_arg, "--format=") {
			format_value := strings.trim_prefix(next_arg, "--format=")
			if format_value == "json" {
				print_rules_new_json()
				os.exit(0)
			}
		}
	}
	
	fmt.println("SXS rules new - Generate custom rules template")
	fmt.println("")
	fmt.println("Usage: sxs rules new [file]")
	fmt.println("")
	fmt.println("Description:")
	fmt.println("  Generate a template for custom security rules.")
	fmt.println("  If no file is specified, saves to:")
	fmt.println("    - $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set)")
	fmt.println("    - ./sxs.json (otherwise)")
	fmt.println("")
	fmt.println("Options:")
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println("Examples:")
	fmt.println("  sxs rules new")
	fmt.println("  sxs rules new custom-rules.json")
	fmt.println("  sxs rules new ./config/")
	os.exit(0)
}

print_policy_new_help :: proc(args: []string, arg_index: int) {
	// Check if format is specified
	if arg_index < len(args) {
		next_arg := args[arg_index]
		// Handle --format json
		if next_arg == "-f" || next_arg == "--format" {
			if arg_index + 1 < len(args) {
				format_arg := args[arg_index + 1]
				if format_arg == "json" {
					print_policy_new_json()
					os.exit(0)
				}
			}
		}
		// Handle --format=json (with equals)
		if strings.has_prefix(next_arg, "--format=") {
			format_value := strings.trim_prefix(next_arg, "--format=")
			if format_value == "json" {
				print_policy_new_json()
				os.exit(0)
			}
		}
	}
	
	fmt.println("SXS policy new - Generate policy configuration template")
	fmt.println("")
	fmt.println("Usage: sxs policy new [file]")
	fmt.println("")
	fmt.println("Description:")
	fmt.println("  Generate a template for policy configuration.")
	fmt.println("  If no file is specified, saves to:")
	fmt.println("    - $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set)")
	fmt.println("    - ./sxs.json (otherwise)")
	fmt.println("")
	fmt.println("Options:")
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println("Examples:")
	fmt.println("  sxs policy new")
	fmt.println("  sxs policy new my-policy.json")
	fmt.println("  sxs policy new ./config/")
	os.exit(0)
}

parse_options :: proc() -> CLI_Options {
	opts: CLI_Options
	opts.dialect = .Auto
	opts.format = .JSON
	opts.block_threshold = "High"
	format_explicit := false

	args := os.args[1:]
	
	i := 0
	for i < len(args) {
		arg := args[i]
		
		if arg == "rules" && i + 1 < len(args) && args[i + 1] == "new" {
			opts.template = "rules"
			i += 2
			// Check for --help after subcommand
			if i < len(args) && (args[i] == "--help" || args[i] == "-h") {
				print_rules_new_help(args, i + 1)
			}
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
			// Check for --help after subcommand
			if i < len(args) && (args[i] == "--help" || args[i] == "-h") {
				print_policy_new_help(args, i + 1)
			}
			// Capture optional file path
			if i < len(args) && !strings.has_prefix(args[i], "-") {
				append(&opts.files, args[i])
				i += 1
			}
			continue
		}
		
		if arg == "--help" || arg == "-h" {
			// Check if next argument is --format or --format=json
			if i + 1 < len(args) {
				next_arg := args[i + 1]
				// Handle --format json
				if next_arg == "-f" || next_arg == "--format" {
					if i + 2 < len(args) {
						format_arg := args[i + 2]
						if format_arg == "json" {
							print_usage_json()
							os.exit(0)
						}
					}
				}
				// Handle --format=json (with equals)
				if strings.has_prefix(next_arg, "--format=") {
					format_value := strings.trim_prefix(next_arg, "--format=")
					if format_value == "json" {
						print_usage_json()
						os.exit(0)
					}
				}
			}
			print_usage()
		}
		if arg == "--version" {
			opts.version = true
			i += 1
			continue
		}
		
		if arg == "--list-rules" {
			opts.list_rules = true
			i += 1
			continue
		}

		if arg == "--validate" {
			opts.validate = true
			if !format_explicit {
				opts.format = .Text
			}
			i += 1
			continue
		}

		if arg == "--ignore" {
			if i + 1 >= len(args) {
				fmt.eprintln("Error: --ignore requires a pattern argument")
				os.exit(1)
			}
			i += 1
			append(&opts.ignore_patterns, args[i])
			i += 1
			continue
		}
		if strings.has_prefix(arg, "--ignore=") {
			pattern := strings.trim_prefix(arg, "--ignore=")
			if pattern == "" {
				fmt.eprintln("Error: --ignore= requires a non-empty pattern")
				os.exit(1)
			}
			append(&opts.ignore_patterns, pattern)
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
			format_explicit = true
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
	
	if len(opts.files) == 0 && !opts.stdin && opts.template == "" && !opts.list_rules && !opts.validate {
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

destroy_finding :: proc(f: formatter.Finding) {
	_ = f
}

path_matches_ignore_pattern :: proc(path, pattern: string) -> bool {
	if path == "" || pattern == "" {
		return false
	}

	matched, err := filepath.match(pattern, path)
	if err == .None && matched {
		return true
	}

	base := filepath.base(path)
	base_matched, base_err := filepath.match(pattern, base)
	return base_err == .None && base_matched
}

finding_is_ignored :: proc(finding: formatter.Finding, patterns: []string) -> bool {
	for pattern in patterns {
		if path_matches_ignore_pattern(finding.location.file, pattern) {
			return true
		}
	}
	return false
}

recompute_blocked_from_findings :: proc(result: ^formatter.Scan_Result, threshold: string) {
	result.blocked = false
	threshold_severity := severity_to_shellx(threshold)
	for finding in result.findings {
		if severity_to_shellx(finding.severity) >= threshold_severity {
			result.blocked = true
			return
		}
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
		data, ok := read_stdin_bytes()
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
			converted := convert_finding(f)
			if finding_is_ignored(converted, opts.ignore_patterns[:]) {
				destroy_finding(converted)
				continue
			}
			append(&result.findings, converted)
		}
		
		result.success = scan_result.success
		result.blocked = scan_result.blocked
			if scan_result.ruleset_version != "" {
				result.ruleset_version = strings.clone(scan_result.ruleset_version)
			}
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
				converted := convert_finding(f)
				if finding_is_ignored(converted, opts.ignore_patterns[:]) {
					destroy_finding(converted)
					continue
				}
				append(&result.findings, converted)
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
	
	recompute_blocked_from_findings(&result, opts.block_threshold)
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

Validation_Error :: struct {
	source: string,
	message: string,
	suggestion: string,
	line: int,
	column: int,
}

config_location_to_string :: proc(loc: config.Config_Location) -> string {
	switch loc {
	case .Local:
		return "local"
	case .Module:
		return "module"
	case .User:
		return "user"
	}
	return "unknown"
}

append_validation_error :: proc(
	errors: ^[dynamic]Validation_Error,
	source: string,
	message: string,
	suggestion := "",
	line := 0,
	column := 0,
) {
	append(errors, Validation_Error{
		source = strings.clone(source),
		message = strings.clone(message),
		suggestion = strings.clone(suggestion),
		line = line,
		column = column,
	})
}

validate_script_content :: proc(
	source_name: string,
	content: string,
	opts: CLI_Options,
	errors: ^[dynamic]Validation_Error,
) -> bool {
	dialect := dialect_to_shellx(opts.dialect)
	if opts.dialect == .Auto {
		if source_name == "<stdin>" {
			dialect = shellx.detect_shell(content)
		} else {
			dialect = shellx.detect_shell_from_path(source_name, content)
		}
	}

	policy := shellx.DEFAULT_SECURITY_SCAN_POLICY
	scan_opts := shellx.DEFAULT_SECURITY_SCAN_OPTIONS
	scan_opts.ast_parse_failure_mode = .FailClosed

	scan_result := shellx.scan_security(content, dialect, policy, source_name, scan_opts)
	defer shellx.destroy_security_scan_result(&scan_result)

	if scan_result.success {
		return true
	}

	if len(scan_result.errors) == 0 {
		append_validation_error(errors, source_name, "Syntax validation failed")
		return false
	}

	for err in scan_result.errors {
		append_validation_error(
			errors,
			source_name,
			err.message,
			err.suggestion,
			err.location.line,
			err.location.column,
		)
	}

	return false
}

read_stdin_bytes :: proc() -> ([]byte, bool) {
	out := make([dynamic]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := os.read(os.stdin, buf)
		if err != nil {
			delete(out)
			return nil, false
		}
		if n == 0 {
			break
		}
		for b in buf[:n] {
			append(&out, b)
		}
	}
	delete(buf)
	return out[:], true
}

run_validate :: proc(opts: CLI_Options, cfg: config.SXS_Config, config_data: string, config_location: config.Config_Location) {
	_ = cfg

	errors := make([dynamic]Validation_Error, 0, 8)

	config_checked := config_data != ""
	config_valid := true
	config_source := "none"
	if config_checked {
		config_source = config_location_to_string(config_location)
	}

	policy_checked := opts.policy_path != ""
	policy_valid := true
	if policy_checked {
		_, policy_errors, ok := shellx.load_security_policy_file(opts.policy_path)
		if !ok {
			policy_valid = false
			for err in policy_errors {
				append_validation_error(
					&errors,
					opts.policy_path,
					err.message,
					err.suggestion,
					err.location.line,
					err.location.column,
				)
			}
		}
	}

	scripts_checked := opts.stdin || len(opts.files) > 0
	scripts_valid := true
	script_count := len(opts.files)
	if opts.stdin {
		script_count += 1
		data, ok := read_stdin_bytes()
		if !ok {
			scripts_valid = false
			append_validation_error(&errors, "<stdin>", "Failed to read from stdin", "Pipe input: cat file.sh | sxs --validate --stdin")
		} else {
			if len(data) == 0 {
				scripts_valid = false
				append_validation_error(&errors, "<stdin>", "No stdin input provided", "Pipe input: cat file.sh | sxs --validate --stdin")
			} else if !validate_script_content("<stdin>", string(data), opts, &errors) {
				scripts_valid = false
			}
			delete(data)
		}
	}

	for file in opts.files {
		data, ok := os.read_entire_file(file)
		if !ok {
			scripts_valid = false
			append_validation_error(&errors, file, "Failed to read file")
			continue
		}

		if !validate_script_content(file, string(data), opts, &errors) {
			scripts_valid = false
		}
		delete(data)
	}

	valid := config_valid && policy_valid && scripts_valid

	switch opts.format {
	case .JSON:
		fmt.println("{")
		fmt.printf("  \"valid\": %v,\n", valid)
		fmt.println("  \"config\": {")
		fmt.printf("    \"checked\": %v,\n", config_checked)
		fmt.printf("    \"source\": \"%s\",\n", escape_json_string(config_source))
		fmt.printf("    \"valid\": %v\n", config_valid)
		fmt.println("  },")
		fmt.println("  \"policy\": {")
		fmt.printf("    \"checked\": %v,\n", policy_checked)
		fmt.printf("    \"path\": \"%s\",\n", escape_json_string(opts.policy_path))
		fmt.printf("    \"valid\": %v\n", policy_valid)
		fmt.println("  },")
		fmt.println("  \"scripts\": {")
		fmt.printf("    \"checked\": %v,\n", scripts_checked)
		fmt.printf("    \"count\": %d,\n", script_count)
		fmt.printf("    \"valid\": %v\n", scripts_valid)
		fmt.println("  },")
		fmt.println("  \"errors\": [")
		for err, i in errors {
			fmt.println("    {")
			fmt.printf("      \"source\": \"%s\",\n", escape_json_string(err.source))
			fmt.printf("      \"message\": \"%s\",\n", escape_json_string(err.message))
			fmt.printf("      \"suggestion\": \"%s\",\n", escape_json_string(err.suggestion))
			fmt.printf("      \"line\": %d,\n", err.line)
			fmt.printf("      \"column\": %d\n", err.column)
			fmt.print("    }")
			if i < len(errors)-1 {
				fmt.print(",")
			}
			fmt.println("")
		}
		fmt.println("  ]")
		fmt.println("}")
	case .Text, .SARIF:
		if valid {
			fmt.println("Validation successful")
		} else {
			fmt.println("Validation failed")
		}

		if opts.verbose {
			fmt.printf("Config: checked=%v source=%s valid=%v\n", config_checked, config_source, config_valid)
			fmt.printf("Policy: checked=%v path=%s valid=%v\n", policy_checked, opts.policy_path, policy_valid)
			fmt.printf("Scripts: checked=%v count=%d valid=%v\n", scripts_checked, script_count, scripts_valid)
		}

		if len(errors) > 0 {
			fmt.println("")
			fmt.println("Errors:")
			for err in errors {
				if err.line > 0 {
					fmt.printf("- %s:%d:%d: %s\n", err.source, err.line, err.column, err.message)
				} else {
					fmt.printf("- %s: %s\n", err.source, err.message)
				}
				if err.suggestion != "" && opts.verbose {
					fmt.printf("  suggestion: %s\n", err.suggestion)
				}
			}
		}
	}

	for err in errors {
		delete(err.source)
		delete(err.message)
		delete(err.suggestion)
	}
	delete(errors)

	if valid {
		os.exit(0)
	}
	os.exit(1)
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
	
	if opts.list_rules {
		list_rules(opts, cfg)
	}

	if opts.validate {
		run_validate(opts, cfg, config_data, config_location)
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
print_usage_json :: proc() {
	json := `{
  "command": "sxs",
  "version": "` + VERSION + `",
  "description": "ShellX Scanner - CLI tool for security scanning shell scripts",
  "usage": [
    "sxs [dialect] <file> [options]",
    "sxs rules new [file]",
    "sxs policy new [file]"
  ],
  "commands": [
    {
      "name": "rules new",
      "description": "Generate custom rules template"
    },
    {
      "name": "policy new", 
      "description": "Generate policy configuration template"
    }
  ],
  "dialects": ["bash", "zsh", "fish", "posix", "auto"],
  "options": [
    {
      "flag": "-f, --format",
      "description": "Output format: json, text, sarif",
      "default": "json"
    },
    {
      "flag": "-p, --policy",
      "description": "Path to policy file"
    },
    {
      "flag": "--stdin",
      "description": "Read from stdin"
    },
    {
      "flag": "-o, --output",
      "description": "Output file",
      "default": "stdout"
    },
    {
      "flag": "--no-builtin",
      "description": "Disable builtin rules"
    },
    {
      "flag": "--block-threshold",
      "description": "Severity to block: Info, Warning, High, Critical",
      "default": "High"
    },
    {
      "flag": "-q, --quiet",
      "description": "Only output findings"
    },
    {
      "flag": "-v, --verbose",
      "description": "Verbose output"
    },
    {
      "flag": "--version",
      "description": "Show version"
    },
    {
      "flag": "--validate",
      "description": "Validate config/policy and shell script syntax"
    },
    {
      "flag": "--ignore",
      "description": "Ignore findings for file paths matching a glob pattern (repeatable)"
    },
    {
      "flag": "-h, --help",
      "description": "Show this help message"
    }
  ],
  "examples": [
    "sxs script.sh",
    "sxs bash script.sh",
    "cat script.sh | sxs --stdin",
    "sxs -f sarif script.sh > results.sarif",
    "sxs rules new",
    "sxs rules new --help",
    "sxs policy new --help",
    "sxs --validate script.sh",
    "sxs --ignore \"vendor/*\" script.sh"
  ]
}`
	fmt.println(json)
}

print_rules_new_json :: proc() {
	json := `{
  "command": "sxs rules new",
  "description": "Generate custom rules template",
  "usage": "sxs rules new [file]",
  "description_detail": "Generate a template for custom security rules. If no file is specified, saves to: $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set) or ./sxs.json (otherwise)",
  "options": [
    {
      "flag": "-h, --help",
      "description": "Show this help message"
    }
  ],
  "examples": [
    "sxs rules new",
    "sxs rules new custom-rules.json",
    "sxs rules new ./config/"
  ]
}`
	fmt.println(json)
}

print_policy_new_json :: proc() {
	json := `{
  "command": "sxs policy new",
  "description": "Generate policy configuration template",
  "usage": "sxs policy new [file]",
  "description_detail": "Generate a template for policy configuration. If no file is specified, saves to: $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set) or ./sxs.json (otherwise)",
  "options": [
    {
      "flag": "-h, --help",
      "description": "Show this help message"
    }
  ],
  "examples": [
    "sxs policy new",
    "sxs policy new my-policy.json",
    "sxs policy new ./config/"
  ]
}`
	fmt.println(json)
}
// Built-in security rules data
Builtin_Rule :: struct {
	id: string,
	severity: string,
	category: string,
	description: string,
}

BUILTIN_RULES :: []Builtin_Rule{
	{"sec.pipe_download_exec", "Critical", "execution", "Download piped to shell"},
	{"sec.eval_download", "Critical", "execution", "Eval with network content"},
	{"sec.dangerous_rm", "Critical", "filesystem", "Destructive rm -rf"},
	{"sec.overpermissive_chmod", "Warning", "permissions", "chmod 777"},
	{"sec.source_tmp", "High", "source", "Source from /tmp"},
	{"sec.ast.eval", "High", "execution", "AST-detected eval"},
	{"sec.ast.dynamic_exec", "Critical", "execution", "Dynamic command substitution"},
	{"sec.ast.source", "High", "source", "Runtime source invocation"},
	{"sec.ast.pipe_download_exec", "Critical", "execution", "AST pipe download to shell"},
	{"sec.ast.shell_dash_c", "High", "execution", "Shell -c execution"},
	{"sec.ast.shell_dash_c_dynamic", "Critical", "execution", "Dynamic -c command"},
	{"sec.ast.source_process_subst", "Critical", "source", "Source process substitution"},
	{"sec.ast.indirect_exec", "High", "execution", "Indirect command execution"},
}

Rule_Info :: struct {
	id: string,
	rule_type: string, // "builtin" or "custom"
	severity: string,
	category: string,
	description: string,
	enabled: bool,
	match_kind: string,
	pattern: string,
	confidence: f32,
}

list_rules :: proc(opts: CLI_Options, cfg: config.SXS_Config) {
	all_rules := make([dynamic]Rule_Info, 0, len(BUILTIN_RULES) + len(cfg.custom_rules))

	for builtin in BUILTIN_RULES {
		info := Rule_Info{
			id = builtin.id,
			rule_type = "builtin",
			severity = builtin.severity,
			category = builtin.category,
			description = builtin.description,
			enabled = cfg.use_builtin_rules,
			match_kind = "builtin",
		}

		for override in cfg.rule_overrides {
			if override.rule_id == builtin.id {
				info.enabled = cfg.use_builtin_rules && override.enabled
				if override.severity_override != "" {
					info.severity = override.severity_override
				}
				break
			}
		}

		append(&all_rules, info)
	}

	for custom_rule in cfg.custom_rules {
		info := Rule_Info{
			id = custom_rule.rule_id,
			rule_type = "custom",
			severity = custom_rule.severity,
			category = custom_rule.category,
			description = custom_rule.message,
			enabled = custom_rule.enabled,
			match_kind = custom_rule.match_kind,
			pattern = custom_rule.pattern,
			confidence = custom_rule.confidence,
		}
		append(&all_rules, info)
	}

	switch opts.format {
	case .JSON:
		list_rules_json(all_rules[:], opts.verbose)
	case .Text:
		list_rules_text(all_rules[:], opts.verbose)
	case .SARIF:
		// SARIF is scan-results format; list-rules falls back to text.
		list_rules_text(all_rules[:], opts.verbose)
	}

	delete(all_rules)
	os.exit(0)
}

list_rules_text :: proc(rules: []Rule_Info, verbose: bool) {
	builtin_count := 0
	custom_count := 0
	enabled_count := 0
	for rule in rules {
		if rule.rule_type == "builtin" {
			builtin_count += 1
		} else {
			custom_count += 1
		}
		if rule.enabled {
			enabled_count += 1
		}
	}

	if verbose {
		fmt.println("SXS Security Rules (verbose)")
		fmt.println("==============================================================================================================")
		fmt.printf("%-30s %-8s %-10s %-12s %-7s %-12s %s\n",
			"ID", "Type", "Severity", "Category", "Enabled", "Match Kind", "Description")
		fmt.println("--------------------------------------------------------------------------------------------------------------")

		for rule in rules {
			enabled := "No"
			if rule.enabled {
				enabled = "Yes"
			}
			fmt.printf("%-30s %-8s %-10s %-12s %-7s %-12s %s\n",
				rule.id,
				rule.rule_type,
				rule.severity,
				rule.category,
				enabled,
				rule.match_kind,
				rule.description)
			if rule.rule_type == "custom" && rule.pattern != "" {
				fmt.printf("  pattern: %s (confidence: %.2f)\n", rule.pattern, rule.confidence)
			}
		}
	} else {
		fmt.println("SXS Security Rules")
		fmt.println("======================================================================================")
		fmt.printf("%-30s %-8s %-10s %-12s %s\n",
			"ID", "Type", "Severity", "Category", "Description")
		fmt.println("--------------------------------------------------------------------------------------")

		for rule in rules {
			fmt.printf("%-30s %-8s %-10s %-12s %s\n",
				rule.id,
				rule.rule_type,
				rule.severity,
				rule.category,
				rule.description)
		}
	}

	fmt.println("")
	fmt.printf("Total: %d (builtin: %d, custom: %d, enabled: %d)\n",
		len(rules), builtin_count, custom_count, enabled_count)
}

list_rules_json :: proc(rules: []Rule_Info, verbose: bool) {
	builtin_count := 0
	custom_count := 0
	enabled_count := 0
	for rule in rules {
		if rule.rule_type == "builtin" {
			builtin_count += 1
		} else {
			custom_count += 1
		}
		if rule.enabled {
			enabled_count += 1
		}
	}

	fmt.println("{")
	fmt.println(`  "command": "sxs --list-rules",`)
	fmt.printf("  \"total_rules\": %d,\n", len(rules))
	fmt.println("  \"counts\": {")
	fmt.printf("    \"builtin\": %d,\n", builtin_count)
	fmt.printf("    \"custom\": %d,\n", custom_count)
	fmt.printf("    \"enabled\": %d\n", enabled_count)
	fmt.println("  },")
	fmt.println("  \"rules\": [")

		for rule, i in rules {
			escaped_id := escape_json_string(rule.id)
			escaped_type := escape_json_string(rule.rule_type)
			escaped_severity := escape_json_string(rule.severity)
		escaped_category := escape_json_string(rule.category)
		escaped_description := escape_json_string(rule.description)
		escaped_match_kind := escape_json_string(rule.match_kind)
		escaped_pattern := escape_json_string(rule.pattern)

		enabled := "false"
		if rule.enabled {
			enabled = "true"
		}

		fmt.println("    {")
		fmt.printf("      \"id\": \"%s\",\n", escaped_id)
		fmt.printf("      \"type\": \"%s\",\n", escaped_type)
		fmt.printf("      \"severity\": \"%s\",\n", escaped_severity)
		fmt.printf("      \"category\": \"%s\",\n", escaped_category)
		fmt.printf("      \"enabled\": %s,\n", enabled)

		if verbose || rule.rule_type == "custom" {
			fmt.printf("      \"description\": \"%s\",\n", escaped_description)
			fmt.printf("      \"match_kind\": \"%s\"", escaped_match_kind)
			if rule.rule_type == "custom" {
				fmt.println(",")
				fmt.printf("      \"pattern\": \"%s\",\n", escaped_pattern)
				fmt.printf("      \"confidence\": %.2f\n", rule.confidence)
			} else {
				fmt.println("")
			}
		} else {
			fmt.printf("      \"description\": \"%s\"\n", escaped_description)
		}

		fmt.print("    }")
			if i < len(rules)-1 {
				fmt.print(",")
			}
			fmt.println("")
			delete(escaped_id)
			delete(escaped_type)
			delete(escaped_severity)
			delete(escaped_category)
			delete(escaped_description)
			delete(escaped_match_kind)
			delete(escaped_pattern)
		}

	fmt.println("  ]")
	fmt.println("}")
}

escape_json_string :: proc(s: string) -> string {
	builder := strings.builder_make()
	for c in s {
		switch c {
		case '"':
			strings.write_string(&builder, "\\\"")
		case '\\':
			strings.write_string(&builder, "\\\\")
		case '\b':
			strings.write_string(&builder, "\\b")
		case '\f':
			strings.write_string(&builder, "\\f")
		case '\n':
			strings.write_string(&builder, "\\n")
		case '\r':
			strings.write_string(&builder, "\\r")
		case '\t':
			strings.write_string(&builder, "\\t")
		case:
			strings.write_rune(&builder, c)
		}
	}
	result := strings.clone(strings.to_string(builder))
	strings.builder_destroy(&builder)
	return result
}
