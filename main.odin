package sxs

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"

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
			continue
		}
		if arg == "policy" && i + 1 < len(args) && args[i + 1] == "new" {
			opts.template = "policy"
			i += 2
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
	
	// Handle version flag before checking for required args
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
			// Remove first element from dynamic array
			for i := 0; i < len(opts.files) - 1; i += 1 {
				opts.files[i] = opts.files[i + 1]
			}
			resize(&opts.files, len(opts.files) - 1)
		}
	}
	
	return opts
}

main :: proc() {
	opts := parse_options()
	
	if opts.template == "rules" {
		print_rules_template(opts.files[0] if len(opts.files) > 0 else "")
		os.exit(0)
	}
	
	if opts.template == "policy" {
		print_policy_template(opts.files[0] if len(opts.files) > 0 else "")
		os.exit(0)
	}
	
	fmt.println("SXS v" + VERSION)
	fmt.println("Dialect:", opts.dialect)
	fmt.println("Format:", opts.format)
	fmt.println("Files:", opts.files)
}

print_rules_template :: proc(path: string) {
	content := `# SXS Custom Rules Template
# Add your custom security rules here

[[rules]]
id = "my.custom.rule"
enabled = true
severity = "High"
match_kind = "Regex"
pattern = "dangerous_pattern"
category = "custom"
confidence = 0.9
message = "Custom rule matched"
suggestion = "Fix the issue"
phases = ["source"]
`
	if path != "" {
		os.write_entire_file(path, transmute([]u8)content)
		fmt.println("Created rules file:", path)
	} else {
		fmt.print(content)
	}
}

print_policy_template :: proc(path: string) {
	content := `# SXS Policy Configuration Template

[policy]
use_builtin_rules = true
block_threshold = "High"

# Paths to skip during scanning
allowlist_paths = []

# Commands to ignore
allowlist_commands = []

# Override builtin rules
# [[policy.rule_overrides]]
# rule_id = "sec.source_tmp"
# enabled = true
# severity_override = "Warning"

# Custom rules (see rules.toml)
# include_rules = ["rules.toml"]
`
	if path != "" {
		os.write_entire_file(path, transmute([]u8)content)
		fmt.println("Created policy file:", path)
	} else {
		fmt.print(content)
	}
}
