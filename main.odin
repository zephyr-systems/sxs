package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

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
	list_policies: bool,
	validate: bool,
	test_rules_path: string,
	ignore_patterns: [dynamic]string,
	ignore_rules: [dynamic]string,
	template: string,
}

print_usage :: proc() {
	use_color := ui_color_enabled()
	c_bold := ui_color(use_color, "\x1b[1m")
	c_dim := ui_color(use_color, "\x1b[2m")
	c_reset := ui_color(use_color, "\x1b[0m")
	fmt.println(ui_join([]string{c_bold, "SXS (ShellX Scanner) v", VERSION, c_reset}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Usage:", c_reset, " sxs [dialect] <file> [options]"}))
	fmt.println("       sxs rules new [file]")
	fmt.println("       sxs policy new [file]")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Commands:", c_reset}))
	fmt.println("  rules new [file]     Generate custom rules template")
	fmt.println("  policy new [file]    Generate policy configuration template")
	fmt.println("")
	fmt.println(ui_join([]string{c_dim, "Dialect (optional): bash, zsh, fish, posix (default: auto)", c_reset}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Options:", c_reset}))
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
	fmt.println("  --list-policies      List available policy sources")
	fmt.println("  --validate           Validate config/policy and shell script syntax (defaults to text output)")
	fmt.println("  --test-rules         Test custom rules from a rules file against input (defaults to text output)")
	fmt.println("  --ignore             Ignore findings for file paths matching a glob (repeatable)")
	fmt.println("  --ignore-rule        Ignore findings for a specific rule_id (repeatable)")
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Examples:", c_reset}))
	fmt.println("  sxs script.sh")
	fmt.println("  sxs bash script.sh")
	fmt.println("  cat script.sh | sxs --stdin")
	fmt.println("  sxs -f sarif script.sh > results.sarif")
	fmt.println("  sxs rules new")
	fmt.println("  sxs rules new --help")
	fmt.println("  sxs policy new --help")
	fmt.println("  sxs --validate script.sh")
	fmt.println("  sxs --test-rules sxs.json script.sh")
	fmt.println("  sxs --ignore 'vendor/*' script.sh")
	fmt.println("  sxs --ignore-rule sec.overpermissive_chmod script.sh")
	fmt.println("  sxs --list-policies")
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
	
	use_color := ui_color_enabled()
	c_bold := ui_color(use_color, "\x1b[1m")
	c_reset := ui_color(use_color, "\x1b[0m")

	fmt.println(ui_join([]string{c_bold, "SXS rules new - Generate custom rules template", c_reset}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Usage:", c_reset, " sxs rules new [file]"}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Description:", c_reset}))
	fmt.println("  Generate a template for custom security rules.")
	fmt.println("  If no file is specified, saves to:")
	fmt.println("    - $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set)")
	fmt.println("    - ./sxs.json (otherwise)")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Options:", c_reset}))
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Examples:", c_reset}))
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
	
	use_color := ui_color_enabled()
	c_bold := ui_color(use_color, "\x1b[1m")
	c_reset := ui_color(use_color, "\x1b[0m")

	fmt.println(ui_join([]string{c_bold, "SXS policy new - Generate policy configuration template", c_reset}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Usage:", c_reset, " sxs policy new [file]"}))
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Description:", c_reset}))
	fmt.println("  Generate a template for policy configuration.")
	fmt.println("  If no file is specified, saves to:")
	fmt.println("    - $ZEPHYR_SXS_DIR/sxs.json (if ZEPHYR_SXS_DIR is set)")
	fmt.println("    - ./sxs.json (otherwise)")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Options:", c_reset}))
	fmt.println("  -h, --help           Show this help message")
	fmt.println("")
	fmt.println(ui_join([]string{c_bold, "Examples:", c_reset}))
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
		if arg == "--list-policies" {
			opts.list_policies = true
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
			if arg == "--test-rules" {
				if i + 1 >= len(args) {
					fmt.eprintln(ui_error_text("--test-rules requires a rules file path"))
					os.exit(1)
				}
				opts.test_rules_path = args[i+1]
				if !format_explicit {
					opts.format = .Text
				}
				i += 2
				continue
			}
			if strings.has_prefix(arg, "--test-rules=") {
				rules_path := strings.trim_prefix(arg, "--test-rules=")
				if rules_path == "" {
					fmt.eprintln(ui_error_text("--test-rules= requires a non-empty rules file path"))
					os.exit(1)
				}
				opts.test_rules_path = rules_path
				if !format_explicit {
					opts.format = .Text
				}
				i += 1
				continue
			}

		if arg == "--ignore" {
			if i + 1 >= len(args) {
				fmt.eprintln(ui_error_text("--ignore requires a pattern argument"))
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
				fmt.eprintln(ui_error_text("--ignore= requires a non-empty pattern"))
				os.exit(1)
			}
			append(&opts.ignore_patterns, pattern)
			i += 1
			continue
		}
		if arg == "--ignore-rule" {
			if i + 1 >= len(args) {
				fmt.eprintln(ui_error_text("--ignore-rule requires a rule_id argument"))
				os.exit(1)
			}
			i += 1
			append(&opts.ignore_rules, args[i])
			i += 1
			continue
		}
		if strings.has_prefix(arg, "--ignore-rule=") {
			rule_id := strings.trim_prefix(arg, "--ignore-rule=")
			if rule_id == "" {
				fmt.eprintln(ui_error_text("--ignore-rule= requires a non-empty rule_id"))
				os.exit(1)
			}
			append(&opts.ignore_rules, rule_id)
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
				fmt.eprintln(ui_error_text("-f/--format requires an argument"))
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
				fmt.eprintln(ui_error_text("invalid format, must be json, text, or sarif"))
				os.exit(1)
			}
			format_explicit = true
			i += 1
			continue
		}
		
		if arg == "-p" || arg == "--policy" {
			if i + 1 >= len(args) {
				fmt.eprintln(ui_error_text("-p/--policy requires an argument"))
				os.exit(1)
			}
			i += 1
			opts.policy_path = args[i]
			i += 1
			continue
		}
		
		if arg == "-o" || arg == "--output" {
			if i + 1 >= len(args) {
				fmt.eprintln(ui_error_text("-o/--output requires an argument"))
				os.exit(1)
			}
			i += 1
			opts.output_path = args[i]
			i += 1
			continue
		}
		
		if arg == "--block-threshold" {
			if i + 1 >= len(args) {
				fmt.eprintln(ui_error_text("--block-threshold requires an argument"))
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
			fmt.eprintln(ui_error_text(ui_join([]string{"unknown flag: ", arg})))
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
	
	if len(opts.files) == 0 && !opts.stdin && opts.template == "" && !opts.list_rules && !opts.list_policies && !opts.validate && opts.test_rules_path == "" {
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

ui_color_enabled :: proc() -> bool {
	if os.get_env("CLICOLOR_FORCE") == "1" {
		return true
	}
	if os.get_env("NO_COLOR") != "" || os.get_env("SXS_NO_COLOR") != "" {
		return false
	}
	term := os.get_env("TERM")
	return term != "" && term != "dumb"
}

ui_color :: proc(enabled: bool, code: string) -> string {
	if enabled {
		return code
	}
	return ""
}

ui_join :: proc(parts: []string) -> string {
	return strings.concatenate(parts)
}

ui_severity_text :: proc(severity: string, use_color: bool) -> string {
	c_reset := ui_color(use_color, "\x1b[0m")
	switch severity {
	case "Critical":
		return ui_join([]string{ui_color(use_color, "\x1b[35;1m"), severity, c_reset})
	case "High":
		return ui_join([]string{ui_color(use_color, "\x1b[31m"), severity, c_reset})
	case "Warning":
		return ui_join([]string{ui_color(use_color, "\x1b[33m"), severity, c_reset})
	case "Info":
		return ui_join([]string{ui_color(use_color, "\x1b[36m"), severity, c_reset})
	}
	return severity
}

ui_error_text :: proc(msg: string) -> string {
	use_color := ui_color_enabled()
	return ui_join([]string{ui_color(use_color, "\x1b[31;1m"), "Error:", ui_color(use_color, "\x1b[0m"), " ", msg})
}

ui_success_text :: proc(msg: string) -> string {
	use_color := ui_color_enabled()
	return ui_join([]string{ui_color(use_color, "\x1b[32;1m"), msg, ui_color(use_color, "\x1b[0m")})
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

wildcard_match :: proc(pattern, text: string) -> bool {
	p := 0
	t := 0
	star := -1
	match := 0

	for t < len(text) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == text[t]) {
			p += 1
			t += 1
			continue
		}

		if p < len(pattern) && pattern[p] == '*' {
			star = p
			match = t
			p += 1
			continue
		}

		if star != -1 {
			p = star + 1
			match += 1
			t = match
			continue
		}

		return false
	}

	for p < len(pattern) && pattern[p] == '*' {
		p += 1
	}

	return p == len(pattern)
}

path_matches_ignore_pattern :: proc(path, pattern: string) -> bool {
	if path == "" || pattern == "" {
		return false
	}

	matched, err := filepath.match(pattern, path)
	if err == .None && matched {
		return true
	}
	if wildcard_match(pattern, path) {
		return true
	}

	trimmed_path := strings.trim_left(path, "/")
	if trimmed_path != path {
		trimmed_matched, trimmed_err := filepath.match(pattern, trimmed_path)
		if trimmed_err == .None && trimmed_matched {
			return true
		}
		if wildcard_match(pattern, trimmed_path) {
			return true
		}
	}

	// Match against path suffixes so patterns like "vendor/*" and "*/vendor/*"
	// work regardless of absolute/relative input path roots.
	for i := 0; i < len(trimmed_path); i += 1 {
		if trimmed_path[i] != '/' {
			continue
		}
		suffix := trimmed_path[i+1:]
		suffix_matched, suffix_err := filepath.match(pattern, suffix)
		if suffix_err == .None && suffix_matched {
			return true
		}
		if wildcard_match(pattern, suffix) {
			return true
		}
	}

	base := filepath.base(path)
	base_matched, base_err := filepath.match(pattern, base)
	if base_err == .None && base_matched {
		return true
	}
	return wildcard_match(pattern, base)
}

finding_is_ignored :: proc(finding: formatter.Finding, patterns: []string) -> bool {
	for pattern in patterns {
		if path_matches_ignore_pattern(finding.location.file, pattern) {
			return true
		}
	}
	return false
}

finding_is_ignored_shellx :: proc(finding: shellx.SecurityFinding, patterns: []string) -> bool {
	for pattern in patterns {
		if path_matches_ignore_pattern(finding.location.file, pattern) {
			return true
		}
	}
	return false
}

finding_rule_is_ignored :: proc(finding: formatter.Finding, ignored_rules: []string) -> bool {
	for rule_id in ignored_rules {
		if finding.rule_id == rule_id {
			return true
		}
	}
	return false
}

finding_rule_is_ignored_shellx :: proc(finding: shellx.SecurityFinding, ignored_rules: []string) -> bool {
	for rule_id in ignored_rules {
		if finding.rule_id == rule_id {
			return true
		}
	}
	return false
}

build_ignored_rule_set :: proc(ignored_rules: []string) -> map[string]bool {
	ignored_rule_set: map[string]bool
	if len(ignored_rules) == 0 {
		return ignored_rule_set
	}
	ignored_rule_set = make(map[string]bool, len(ignored_rules))
	for rule_id in ignored_rules {
		if rule_id != "" {
			ignored_rule_set[rule_id] = true
		}
	}
	return ignored_rule_set
}

finding_rule_is_ignored_shellx_set :: proc(finding: shellx.SecurityFinding, ignored_rule_set: map[string]bool) -> bool {
	if len(ignored_rule_set) == 0 {
		return false
	}
	_, ok := ignored_rule_set[finding.rule_id]
	return ok
}

inline_ignore_matches_rule :: proc(line: string, rule_id: string) -> bool {
	marker := "sxs-ignore:"
	idx := strings.index(line, marker)
	if idx < 0 {
		return false
	}

	tail := strings.trim_space(line[idx+len(marker):])
	if tail == "" {
		return false
	}

	start := 0
	for start < len(tail) {
		end := start
		for end < len(tail) && tail[end] != ',' {
			end += 1
		}

		token := strings.trim_space(tail[start:end])
		if token == rule_id || strings.equal_fold(token, "all") {
			return true
		}

		start = end + 1
	}

	return false
}

finding_is_inline_ignored :: proc(finding: formatter.Finding, source_lines: []string) -> bool {
	if finding.location.line <= 0 {
		return false
	}

	line_idx := finding.location.line - 1
	if line_idx < len(source_lines) && inline_ignore_matches_rule(source_lines[line_idx], finding.rule_id) {
		return true
	}

	prev_idx := line_idx - 1
	if prev_idx >= 0 && prev_idx < len(source_lines) && inline_ignore_matches_rule(source_lines[prev_idx], finding.rule_id) {
		return true
	}

	return false
}

finding_is_inline_ignored_shellx :: proc(finding: shellx.SecurityFinding, source_lines: []string) -> bool {
	if finding.location.line <= 0 {
		return false
	}

	line_idx := finding.location.line - 1
	if line_idx < len(source_lines) && inline_ignore_matches_rule(source_lines[line_idx], finding.rule_id) {
		return true
	}

	prev_idx := line_idx - 1
	if prev_idx >= 0 && prev_idx < len(source_lines) && inline_ignore_matches_rule(source_lines[prev_idx], finding.rule_id) {
		return true
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

File_Scan_Result :: struct {
	success: bool,
	blocked: bool,
	findings: [dynamic]formatter.Finding,
	errors: [dynamic]string,
	ruleset_version: string,
	stats: formatter.Scan_Stats,
}

Parallel_Scan_Context :: struct {
	files: []string,
	results: []File_Scan_Result,
	opts: CLI_Options,
	policy: shellx.SecurityScanPolicy,
	options: shellx.SecurityScanOptions,
	ignored_rule_set: map[string]bool,
	profile_enabled: bool,
	next_index: int,
	chunk_size: int,
	index_mutex: sync.Mutex,
}

internal_profile_enabled :: proc() -> bool {
	return os.get_env("SXS_INTERNAL_PROFILE") == "1"
}

resolve_worker_count :: proc(file_count: int) -> int {
	if file_count < 1 {
		return 1
	}

	core_count := os.processor_core_count()
	if core_count < 1 {
		core_count = 1
	}
	worker_count := core_count

	if override := strings.trim_space(os.get_env("SXS_WORKERS")); override != "" {
		if parsed, ok := strconv.parse_int(override); ok && parsed > 0 {
			worker_count = parsed
		}
	}

	if worker_count < 1 {
		worker_count = 1
	}
	if worker_count > file_count {
		worker_count = file_count
	}
	return worker_count
}

scan_single_file :: proc(
	file: string,
	opts: CLI_Options,
	policy: shellx.SecurityScanPolicy,
	options: shellx.SecurityScanOptions,
	ignored_rule_set: map[string]bool,
	profile_enabled: bool,
) -> File_Scan_Result {
	file_sw: time.Stopwatch
	if profile_enabled {
		time.stopwatch_start(&file_sw)
	}
	file_result := File_Scan_Result{
		success = true,
		findings = make([dynamic]formatter.Finding, 0, 8),
		errors = make([dynamic]string, 0, 2),
	}

	if !os.exists(file) {
		append(&file_result.errors, strings.concatenate([]string{"File not found: ", file}))
		return file_result
	}

	data, ok := os.read_entire_file(file)
	if !ok {
		append(&file_result.errors, strings.concatenate([]string{"Failed to read file: ", file}))
		return file_result
	}
	defer delete(data)

	source_text := string(data)
	has_path_ignores := len(opts.ignore_patterns) > 0
	has_rule_ignores := len(ignored_rule_set) > 0
	has_inline_ignores := strings.contains(source_text, "sxs-ignore:")
	source_lines: []string
	if has_inline_ignores {
		source_lines = strings.split_lines(source_text)
		defer delete(source_lines)
	}

	shell_dialect := dialect_to_shellx(opts.dialect)
	if opts.dialect == .Auto {
		shell_dialect = shellx.detect_shell_from_path(file, source_text)
	}

	scan_result := shellx.scan_security(source_text, shell_dialect, policy, file, options)
	if profile_enabled {
		time.stopwatch_stop(&file_sw)
		file_wall_ms := i64(time.duration_milliseconds(time.stopwatch_duration(file_sw)))
		fmt.eprintln(fmt.aprintf(
			"[sxs] file scan (%s): success=%v blocked=%v findings=%d lines=%d rules_evaluated=%d ruleset=%s builtin=%v wall_ms=%d shellx_ms=%d",
			file,
			scan_result.success,
			scan_result.blocked,
			len(scan_result.findings),
			scan_result.stats.lines_scanned,
			scan_result.stats.rules_evaluated,
			scan_result.ruleset_version,
			policy.use_builtin_rules,
			file_wall_ms,
			scan_result.stats.duration_ms,
		))
	} else if opts.verbose {
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
		ignored := false
		if has_path_ignores && finding_is_ignored_shellx(f, opts.ignore_patterns[:]) {
			ignored = true
		}
		if !ignored && has_rule_ignores && finding_rule_is_ignored_shellx_set(f, ignored_rule_set) {
			ignored = true
		}
		if !ignored && has_inline_ignores && finding_is_inline_ignored_shellx(f, source_lines[:]) {
			ignored = true
		}
		if ignored {
			continue
		}
		append(&file_result.findings, convert_finding(f))
	}

	file_result.success = scan_result.success
	file_result.blocked = scan_result.blocked
	file_result.stats = formatter.Scan_Stats{
		files_scanned = 1,
		lines_scanned = scan_result.stats.lines_scanned,
		rules_evaluated = scan_result.stats.rules_evaluated,
		duration_ms = scan_result.stats.duration_ms,
	}
	if scan_result.ruleset_version != "" {
		file_result.ruleset_version = strings.clone(scan_result.ruleset_version)
	}

	shellx.destroy_security_scan_result(&scan_result)
	return file_result
}

parallel_scan_worker :: proc(ctx: ^Parallel_Scan_Context) {
	for {
		sync.mutex_lock(&ctx.index_mutex)
		start := ctx.next_index
		if start >= len(ctx.files) {
			sync.mutex_unlock(&ctx.index_mutex)
			return
		}
		end := start + ctx.chunk_size
		if end > len(ctx.files) {
			end = len(ctx.files)
		}
		ctx.next_index = end
		sync.mutex_unlock(&ctx.index_mutex)

		for i := start; i < end; i += 1 {
			file := ctx.files[i]
			ctx.results[i] = scan_single_file(file, ctx.opts, ctx.policy, ctx.options, ctx.ignored_rule_set, ctx.profile_enabled)
		}
	}
}

aggregate_file_scan_result :: proc(result: ^formatter.Scan_Result, file_result: File_Scan_Result) {
	result.success = result.success && file_result.success
	if file_result.blocked {
		result.blocked = true
	}

	for err in file_result.errors {
		append(&result.errors, err)
	}
	for finding in file_result.findings {
		append(&result.findings, finding)
	}

	result.stats.files_scanned += file_result.stats.files_scanned
	result.stats.lines_scanned += file_result.stats.lines_scanned
	result.stats.rules_evaluated += file_result.stats.rules_evaluated
	result.stats.duration_ms += file_result.stats.duration_ms
	if result.ruleset_version == "" && file_result.ruleset_version != "" {
		result.ruleset_version = strings.clone(file_result.ruleset_version)
	}
}

run_scan :: proc(opts: CLI_Options, cfg: config.SXS_Config) -> formatter.Scan_Result {
	profile_enabled := internal_profile_enabled()
	total_sw: time.Stopwatch
	if profile_enabled {
		time.stopwatch_start(&total_sw)
	}
	policy_prep_sw: time.Stopwatch
	if profile_enabled {
		time.stopwatch_start(&policy_prep_sw)
	}
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

	policy_prep_ms: i64
	if profile_enabled {
		time.stopwatch_stop(&policy_prep_sw)
		policy_prep_ms = i64(time.duration_milliseconds(time.stopwatch_duration(policy_prep_sw)))
	}
	scan_exec_sw: time.Stopwatch
	if profile_enabled {
		time.stopwatch_start(&scan_exec_sw)
	}
	
	options := shellx.DEFAULT_SECURITY_SCAN_OPTIONS
	shell_dialect := dialect_to_shellx(opts.dialect)
	ignored_rule_set := build_ignored_rule_set(opts.ignore_rules[:])
	
	if opts.stdin {
		data, ok := read_stdin_bytes()
		if !ok {
			result.success = false
			append(&result.errors, "Failed to read from stdin")
			return result
		}
		source_text := string(data)
		has_path_ignores := len(opts.ignore_patterns) > 0
		has_rule_ignores := len(ignored_rule_set) > 0
		has_inline_ignores := strings.contains(source_text, "sxs-ignore:")
		source_lines: []string
		if has_inline_ignores {
			source_lines = strings.split_lines(source_text)
		}
		
		if opts.dialect == .Auto {
			shell_dialect = shellx.detect_shell(source_text)
		}
		
		scan_result := shellx.scan_security(source_text, shell_dialect, policy, "<stdin>", options)
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
			ignored := false
			if has_path_ignores && finding_is_ignored_shellx(f, opts.ignore_patterns[:]) {
				ignored = true
			}
			if !ignored && has_rule_ignores && finding_rule_is_ignored_shellx_set(f, ignored_rule_set) {
				ignored = true
			}
			if !ignored && has_inline_ignores && finding_is_inline_ignored_shellx(f, source_lines[:]) {
				ignored = true
			}
			if ignored {
				continue
			}
			append(&result.findings, convert_finding(f))
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
		if has_inline_ignores {
			delete(source_lines)
		}
		delete(data)
	} else {
		if thread.IS_SUPPORTED && len(opts.files) > 1 {
			worker_count := resolve_worker_count(len(opts.files))

			if opts.verbose {
				workers_override := os.get_env("SXS_WORKERS")
				if workers_override != "" {
					fmt.eprintln(fmt.aprintf("[sxs] parallel scan enabled: files=%d workers=%d (SXS_WORKERS=%s)", len(opts.files), worker_count, workers_override))
				} else {
					fmt.eprintln(fmt.aprintf("[sxs] parallel scan enabled: files=%d workers=%d", len(opts.files), worker_count))
				}
			}
			chunk_size := len(opts.files) / (worker_count * 4)
			if chunk_size < 1 {
				chunk_size = 1
			} else if chunk_size > 32 {
				chunk_size = 32
			}

			file_results := make([]File_Scan_Result, len(opts.files))
			ctx := Parallel_Scan_Context{
				files = opts.files[:],
				results = file_results,
				opts = opts,
				policy = policy,
				options = options,
				ignored_rule_set = ignored_rule_set,
				profile_enabled = profile_enabled,
				chunk_size = chunk_size,
			}

			threads := make([dynamic]^thread.Thread, 0, worker_count)
			for i := 0; i < worker_count; i += 1 {
				worker := thread.create_and_start_with_poly_data(&ctx, parallel_scan_worker)
				append(&threads, worker)
			}
			for t in threads {
				thread.destroy(t)
			}
			delete(threads)

			for file_result in file_results {
				aggregate_file_scan_result(&result, file_result)
			}
			delete(file_results)
		} else {
			for file in opts.files {
				file_result := scan_single_file(file, opts, policy, options, ignored_rule_set, profile_enabled)
				aggregate_file_scan_result(&result, file_result)
			}
		}
	}

	scan_exec_ms: i64
	if profile_enabled {
		time.stopwatch_stop(&scan_exec_sw)
		scan_exec_ms = i64(time.duration_milliseconds(time.stopwatch_duration(scan_exec_sw)))
	}
	finalize_sw: time.Stopwatch
	if profile_enabled {
		time.stopwatch_start(&finalize_sw)
	}
	
	recompute_blocked_from_findings(&result, opts.block_threshold)
	finalize_ms: i64
	total_ms: i64
	if profile_enabled {
		time.stopwatch_stop(&finalize_sw)
		finalize_ms = i64(time.duration_milliseconds(time.stopwatch_duration(finalize_sw)))
		time.stopwatch_stop(&total_sw)
		total_ms = i64(time.duration_milliseconds(time.stopwatch_duration(total_sw)))
		fmt.eprintln(fmt.aprintf(
			"[sxs] timings: policy_prep_ms=%d scan_exec_ms=%d finalize_ms=%d total_ms=%d",
			policy_prep_ms,
			scan_exec_ms,
			finalize_ms,
			total_ms,
		))
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
		use_color := ui_color_enabled()
		c_bold := ui_color(use_color, "\x1b[1m")
		c_green := ui_color(use_color, "\x1b[32m")
		c_red := ui_color(use_color, "\x1b[31m")
		c_yellow := ui_color(use_color, "\x1b[33m")
		c_reset := ui_color(use_color, "\x1b[0m")
		if valid {
			fmt.println(ui_join([]string{c_bold, c_green, "Validation successful", c_reset}))
		} else {
			fmt.println(ui_join([]string{c_bold, c_red, "Validation failed", c_reset}))
		}

		if opts.verbose {
			fmt.printf("Config: checked=%v source=%s valid=%v\n", config_checked, config_source, config_valid)
			fmt.printf("Policy: checked=%v path=%s valid=%v\n", policy_checked, opts.policy_path, policy_valid)
			fmt.printf("Scripts: checked=%v count=%d valid=%v\n", scripts_checked, script_count, scripts_valid)
		}

		if len(errors) > 0 {
			fmt.println("")
			fmt.println(ui_join([]string{c_yellow, "Errors:", c_reset}))
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

run_test_rules :: proc(opts: CLI_Options) {
	if opts.test_rules_path == "" {
		fmt.eprintln(ui_error_text("--test-rules requires a rules file path"))
		os.exit(2)
	}

	if !opts.stdin && len(opts.files) == 0 {
		fmt.eprintln(ui_error_text("--test-rules requires an input file or --stdin"))
		os.exit(2)
	}

	rules_data, ok := os.read_entire_file(opts.test_rules_path)
	if !ok {
		fmt.eprintln(ui_error_text(ui_join([]string{"failed to read rules file: ", opts.test_rules_path})))
		os.exit(2)
	}

	rules_cfg, parsed_ok := config.parse_sxs_config(string(rules_data))
	if !parsed_ok {
		fmt.eprintln(ui_error_text("failed to parse rules file JSON"))
		os.exit(2)
	}

	valid_cfg, err_msg := config.validate_sxs_config(&rules_cfg)
	if !valid_cfg {
		fmt.eprintln(ui_error_text(ui_join([]string{"rules file validation failed: ", err_msg})))
		os.exit(2)
	}

	enabled_custom_rules := 0
	for rule in rules_cfg.custom_rules {
		if rule.enabled {
			enabled_custom_rules += 1
		}
	}
	if enabled_custom_rules == 0 {
		fmt.eprintln(ui_error_text("rules file has no enabled custom_rules"))
		os.exit(2)
	}

	test_cfg := config.SXS_Config{
		use_builtin_rules = false,
		block_threshold = "Info",
		custom_rules = rules_cfg.custom_rules,
	}

	test_opts := opts
	test_opts.no_builtin = true
	test_opts.block_threshold = "Info"
	test_opts.policy_path = ""

	result := run_scan(test_opts, test_cfg)

	source := ""
	if len(test_opts.files) > 0 {
		source = test_opts.files[0]
	} else if test_opts.stdin {
		source = "<stdin>"
	}

	output: string
	switch test_opts.format {
	case .JSON:
		output = formatter.format_result_json(result, !test_opts.quiet)
	case .Text:
		output = formatter.format_result_text(result, test_opts.verbose, source)
	case .SARIF:
		output = formatter.format_result_sarif(result, source, VERSION)
	}

	if test_opts.output_path != "" {
		os.write_entire_file(test_opts.output_path, transmute([]u8)output)
	} else {
		fmt.println(output)
	}

	if !result.success {
		os.exit(2)
	}
	if len(result.findings) > 0 {
		os.exit(1)
	}
	os.exit(0)
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
				fmt.eprintln(ui_error_text(ui_join([]string{"config validation failed: ", err_msg})))
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
	if opts.list_policies {
		list_policies(opts, cfg, config_data, config_location)
	}

	if opts.validate {
		run_validate(opts, cfg, config_data, config_location)
	}

	if opts.test_rules_path != "" {
		run_test_rules(opts)
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
	fmt.println(ui_success_text(ui_join([]string{"Created rules template: ", output_path})))
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
	fmt.println(ui_success_text(ui_join([]string{"Created policy template: ", output_path})))
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
      "flag": "--list-rules",
      "description": "List all available security rules"
    },
    {
      "flag": "--list-policies",
      "description": "List available policy sources"
    },
    {
      "flag": "--test-rules",
      "description": "Test custom rules from a rules file against input"
    },
    {
      "flag": "--ignore",
      "description": "Ignore findings for file paths matching a glob pattern (repeatable)"
    },
    {
      "flag": "--ignore-rule",
      "description": "Ignore findings for a specific rule_id (repeatable)"
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
    "sxs --list-rules",
    "sxs --list-policies",
    "sxs --validate script.sh",
    "sxs --test-rules sxs.json script.sh",
    "sxs --ignore \"vendor/*\" script.sh",
    "sxs --ignore-rule sec.overpermissive_chmod script.sh"
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

Policy_Info :: struct {
	name: string,
	policy_type: string, // "builtin", "config", "file"
	source: string,
	description: string,
	active: bool,
	valid: bool,
	use_builtin_rules: bool,
	block_threshold: string,
	ruleset_version: string,
	custom_rules: int,
	rule_overrides: int,
	allowlist_paths: int,
	allowlist_commands: int,
	load_error: string,
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

config_location_path :: proc(loc: config.Config_Location) -> string {
	switch loc {
	case .Local:
		return "./sxs.json"
	case .Module:
		home := os.get_env("HOME")
		if home == "" {
			return "~/.zephyr/modules/sxs/config.json"
		}
		return strings.concatenate([]string{home, "/.zephyr/modules/sxs/config.json"})
	case .User:
		home := os.get_env("HOME")
		if home == "" {
			return "~/.config/sxs/config.json"
		}
		return strings.concatenate([]string{home, "/.config/sxs/config.json"})
	}
	return ""
}

list_policies :: proc(opts: CLI_Options, cfg: config.SXS_Config, config_data: string, config_location: config.Config_Location) {
	policies := make([dynamic]Policy_Info, 0, 3)
	default_policy := shellx.DEFAULT_SECURITY_SCAN_POLICY

	append(&policies, Policy_Info{
		name = "default",
		policy_type = "builtin",
		source = "shellx.DEFAULT_SECURITY_SCAN_POLICY",
		description = "Built-in baseline policy",
		active = true,
		valid = true,
		use_builtin_rules = default_policy.use_builtin_rules,
		block_threshold = severity_to_string(default_policy.block_threshold),
		ruleset_version = default_policy.ruleset_version,
		custom_rules = len(default_policy.custom_rules),
		rule_overrides = len(default_policy.rule_overrides),
		allowlist_paths = len(default_policy.allowlist_paths),
		allowlist_commands = len(default_policy.allowlist_commands),
	})

	if config_data != "" {
		cfg_copy := cfg
		config_valid, config_err := config.validate_sxs_config(&cfg_copy)
		block_threshold := cfg.block_threshold
		if block_threshold == "" {
			block_threshold = "High"
		}
		ruleset_version := cfg.ruleset_version
		if ruleset_version == "" {
			ruleset_version = default_policy.ruleset_version
		}

		append(&policies, Policy_Info{
			name = strings.concatenate([]string{"config/", strings.to_lower(config_location_to_string(config_location))}),
			policy_type = "config",
			source = config_location_path(config_location),
			description = "SXS configuration policy overlays",
			active = opts.policy_path == "",
			valid = config_valid,
			use_builtin_rules = cfg.use_builtin_rules,
			block_threshold = block_threshold,
			ruleset_version = ruleset_version,
			custom_rules = len(cfg.custom_rules),
			rule_overrides = len(cfg.rule_overrides),
			allowlist_paths = len(cfg.allowlist_paths),
			allowlist_commands = len(cfg.allowlist_commands),
			load_error = config_err,
		})
	}

	if opts.policy_path != "" {
		policy, errs, ok := shellx.load_security_policy_file(opts.policy_path)
		load_err := ""
		if !ok && len(errs) > 0 {
			load_err = errs[0].message
		}

		append(&policies, Policy_Info{
			name = "policy-file",
			policy_type = "file",
			source = opts.policy_path,
			description = "Policy loaded from --policy",
			active = ok,
			valid = ok,
			use_builtin_rules = policy.use_builtin_rules,
			block_threshold = severity_to_string(policy.block_threshold),
			ruleset_version = policy.ruleset_version,
			custom_rules = len(policy.custom_rules),
			rule_overrides = len(policy.rule_overrides),
			allowlist_paths = len(policy.allowlist_paths),
			allowlist_commands = len(policy.allowlist_commands),
			load_error = load_err,
		})
	}

	switch opts.format {
	case .JSON:
		list_policies_json(policies[:], opts.verbose)
	case .Text:
		list_policies_text(policies[:], opts.verbose)
	case .SARIF:
		// SARIF is scan-results format; list-policies falls back to text.
		list_policies_text(policies[:], opts.verbose)
	}

	delete(policies)
	os.exit(0)
}

list_rules_text :: proc(rules: []Rule_Info, verbose: bool) {
	use_color := ui_color_enabled()
	c_bold := ui_color(use_color, "\x1b[1m")
	c_dim := ui_color(use_color, "\x1b[2m")
	c_green := ui_color(use_color, "\x1b[32m")
	c_red := ui_color(use_color, "\x1b[31m")
	c_reset := ui_color(use_color, "\x1b[0m")

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
		fmt.println(ui_join([]string{c_bold, "SXS Security Rules (verbose)", c_reset}))
		fmt.println("==============================================================================================================")
		fmt.printf("%-30s %-8s %-10s %-12s %-7s %-12s %s\n",
			"ID", "Type", "Severity", "Category", "Enabled", "Match Kind", "Description")
		fmt.println(ui_join([]string{c_dim, "--------------------------------------------------------------------------------------------------------------", c_reset}))

		for rule in rules {
			enabled := ui_join([]string{c_red, "No", c_reset})
			if rule.enabled {
				enabled = ui_join([]string{c_green, "Yes", c_reset})
			}
			severity := ui_severity_text(rule.severity, use_color)
			fmt.printf("%-30s %-8s %-10s %-12s %-7s %-12s %s\n",
				rule.id,
				rule.rule_type,
				severity,
				rule.category,
				enabled,
				rule.match_kind,
				rule.description)
			if rule.rule_type == "custom" && rule.pattern != "" {
				fmt.printf("  pattern: %s (confidence: %.2f)\n", rule.pattern, rule.confidence)
			}
		}
	} else {
		fmt.println(ui_join([]string{c_bold, "SXS Security Rules", c_reset}))
		fmt.println("======================================================================================")
		fmt.printf("%-30s %-8s %-10s %-12s %s\n",
			"ID", "Type", "Severity", "Category", "Description")
		fmt.println(ui_join([]string{c_dim, "--------------------------------------------------------------------------------------", c_reset}))

		for rule in rules {
			severity := ui_severity_text(rule.severity, use_color)
			fmt.printf("%-30s %-8s %-10s %-12s %s\n",
				rule.id,
				rule.rule_type,
				severity,
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

list_policies_text :: proc(policies: []Policy_Info, verbose: bool) {
	use_color := ui_color_enabled()
	c_bold := ui_color(use_color, "\x1b[1m")
	c_dim := ui_color(use_color, "\x1b[2m")
	c_green := ui_color(use_color, "\x1b[32m")
	c_red := ui_color(use_color, "\x1b[31m")
	c_reset := ui_color(use_color, "\x1b[0m")

	active_count := 0
	valid_count := 0
	for p in policies {
		if p.active {
			active_count += 1
		}
		if p.valid {
			valid_count += 1
		}
	}

	if verbose {
		fmt.println(ui_join([]string{c_bold, "SXS Policies (verbose)", c_reset}))
		fmt.println("==============================================================================================================================")
		fmt.printf("%-14s %-8s %-7s %-7s %-8s %-10s %-20s %s\n",
			"Name", "Type", "Active", "Valid", "Builtin", "Block", "Ruleset", "Source")
		fmt.println(ui_join([]string{c_dim, "------------------------------------------------------------------------------------------------------------------------------", c_reset}))
		for p in policies {
			active := ui_join([]string{c_red, "No", c_reset})
			if p.active {
				active = ui_join([]string{c_green, "Yes", c_reset})
			}
			valid := ui_join([]string{c_red, "No", c_reset})
			if p.valid {
				valid = ui_join([]string{c_green, "Yes", c_reset})
			}
			use_builtin := ui_join([]string{c_red, "No", c_reset})
			if p.use_builtin_rules {
				use_builtin = ui_join([]string{c_green, "Yes", c_reset})
			}
			fmt.printf("%-14s %-8s %-7s %-7s %-8s %-10s %-20s %s\n",
				p.name,
				p.policy_type,
				active,
				valid,
				use_builtin,
				p.block_threshold,
				p.ruleset_version,
				p.source)
			fmt.printf("  custom_rules=%d rule_overrides=%d allowlist_paths=%d allowlist_commands=%d\n",
				p.custom_rules, p.rule_overrides, p.allowlist_paths, p.allowlist_commands)
			if p.load_error != "" {
				fmt.printf("  %serror%s: %s\n", c_red, c_reset, p.load_error)
			}
		}
	} else {
		fmt.println(ui_join([]string{c_bold, "SXS Policies", c_reset}))
		fmt.println("====================================================================================================")
		fmt.printf("%-14s %-8s %-7s %-7s %s\n",
			"Name", "Type", "Active", "Valid", "Source")
		fmt.println(ui_join([]string{c_dim, "----------------------------------------------------------------------------------------------------", c_reset}))
		for p in policies {
			active := ui_join([]string{c_red, "No", c_reset})
			if p.active {
				active = ui_join([]string{c_green, "Yes", c_reset})
			}
			valid := ui_join([]string{c_red, "No", c_reset})
			if p.valid {
				valid = ui_join([]string{c_green, "Yes", c_reset})
			}
			fmt.printf("%-14s %-8s %-7s %-7s %s\n",
				p.name,
				p.policy_type,
				active,
				valid,
				p.source)
		}
	}

	fmt.println("")
	fmt.printf("Total: %d (active: %d, valid: %d)\n", len(policies), active_count, valid_count)
}

list_policies_json :: proc(policies: []Policy_Info, verbose: bool) {
	active_count := 0
	valid_count := 0
	for p in policies {
		if p.active {
			active_count += 1
		}
		if p.valid {
			valid_count += 1
		}
	}

	fmt.println("{")
	fmt.println(`  "command": "sxs --list-policies",`)
	fmt.printf("  \"total_policies\": %d,\n", len(policies))
	fmt.println("  \"counts\": {")
	fmt.printf("    \"active\": %d,\n", active_count)
	fmt.printf("    \"valid\": %d\n", valid_count)
	fmt.println("  },")
	fmt.println("  \"policies\": [")
	for p, i in policies {
		escaped_name := escape_json_string(p.name)
		escaped_type := escape_json_string(p.policy_type)
		escaped_source := escape_json_string(p.source)
		escaped_description := escape_json_string(p.description)
		escaped_block_threshold := escape_json_string(p.block_threshold)
		escaped_ruleset := escape_json_string(p.ruleset_version)
		escaped_error := escape_json_string(p.load_error)

		active := "false"
		if p.active {
			active = "true"
		}
		valid := "false"
		if p.valid {
			valid = "true"
		}
		use_builtin := "false"
		if p.use_builtin_rules {
			use_builtin = "true"
		}

		fmt.println("    {")
		fmt.printf("      \"name\": \"%s\",\n", escaped_name)
		fmt.printf("      \"type\": \"%s\",\n", escaped_type)
		fmt.printf("      \"source\": \"%s\",\n", escaped_source)
		fmt.printf("      \"active\": %s,\n", active)
		fmt.printf("      \"valid\": %s,\n", valid)
		if verbose {
			fmt.printf("      \"description\": \"%s\",\n", escaped_description)
			fmt.printf("      \"use_builtin_rules\": %s,\n", use_builtin)
			fmt.printf("      \"block_threshold\": \"%s\",\n", escaped_block_threshold)
			fmt.printf("      \"ruleset_version\": \"%s\",\n", escaped_ruleset)
			fmt.printf("      \"custom_rules\": %d,\n", p.custom_rules)
			fmt.printf("      \"rule_overrides\": %d,\n", p.rule_overrides)
			fmt.printf("      \"allowlist_paths\": %d,\n", p.allowlist_paths)
			fmt.printf("      \"allowlist_commands\": %d,\n", p.allowlist_commands)
			fmt.printf("      \"error\": \"%s\"\n", escaped_error)
		} else {
			fmt.printf("      \"description\": \"%s\"\n", escaped_description)
		}
		fmt.print("    }")
		if i < len(policies)-1 {
			fmt.print(",")
		}
		fmt.println("")

		delete(escaped_name)
		delete(escaped_type)
		delete(escaped_source)
		delete(escaped_description)
		delete(escaped_block_threshold)
		delete(escaped_ruleset)
		delete(escaped_error)
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
