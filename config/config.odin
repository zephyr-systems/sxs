package config

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"

Config_Location :: enum {
	Local,
	Module,
	User,
}

load_config_tier :: proc(path: string) -> (string, bool) {
	if !os.exists(path) {
		return "", false
	}
	data, ok := os.read_entire_file(path)
	if !ok {
		return "", false
	}
	return string(data), true
}

find_config :: proc() -> (string, Config_Location) {
	// Tier 1: Local ./sxs.json
	if data, ok := load_config_tier("sxs.json"); ok {
		return data, .Local
	}
	
	// Tier 2: Module ~/.zephyr/modules/sxs/config.json
	home := os.get_env("HOME")
	if home != "" {
		module_path := strings.concatenate([]string{home, "/.zephyr/modules/sxs/config.json"})
		if data, ok := load_config_tier(module_path); ok {
			return data, .Module
		}
	}
	
	// Tier 3: User ~/.config/sxs/config.json
	if home != "" {
		user_path := strings.concatenate([]string{home, "/.config/sxs/config.json"})
		if data, ok := load_config_tier(user_path); ok {
			return data, .User
		}
	}
	
	return "", .Local
}

Rule_Override :: struct {
	rule_id: string,
	enabled: bool,
	severity_override: string,
}

Custom_Rule :: struct {
	rule_id: string,
	enabled: bool,
	severity: string,
	match_kind: string,
	pattern: string,
	category: string,
	confidence: f32,
	phases: [dynamic]string,
	command_name: string,
	arg_pattern: string,
	message: string,
	suggestion: string,
}

SXS_Config :: struct {
	use_builtin_rules: bool,
	block_threshold: string,
	ruleset_version: string,
	allowlist_paths: [dynamic]string,
	allowlist_commands: [dynamic]string,
	rule_overrides: [dynamic]Rule_Override,
	custom_rules: [dynamic]Custom_Rule,
}

default_sxs_config :: proc() -> SXS_Config {
	return SXS_Config{
		use_builtin_rules = true,
		block_threshold = "High",
		allowlist_paths = make([dynamic]string),
		allowlist_commands = make([dynamic]string),
		rule_overrides = make([dynamic]Rule_Override),
		custom_rules = make([dynamic]Custom_Rule),
	}
}

validate_sxs_config :: proc(cfg: ^SXS_Config) -> (bool, string) {
	// Validate block_threshold
	switch cfg.block_threshold {
	case "Info", "Warning", "High", "Critical":
		// Valid
	case "":
		// Empty is OK, will use default
	case:
		return false, fmt.aprintf("Invalid block_threshold: %s (must be Info, Warning, High, or Critical)", cfg.block_threshold)
	}
	
	// Validate rule_overrides
	for override in cfg.rule_overrides {
		if override.rule_id == "" {
			return false, "Rule override missing rule_id"
		}
		if override.severity_override != "" {
			switch override.severity_override {
			case "Info", "Warning", "High", "Critical":
				// Valid
			case:
				return false, fmt.aprintf("Invalid severity_override in rule %s: %s", override.rule_id, override.severity_override)
			}
		}
	}
	
	// Validate custom_rules
	for rule in cfg.custom_rules {
		if rule.rule_id == "" {
			return false, "Custom rule missing rule_id"
		}
		if rule.enabled {
			if rule.pattern == "" {
				return false, fmt.aprintf("Custom rule %s missing pattern", rule.rule_id)
			}
			if rule.message == "" {
				return false, fmt.aprintf("Custom rule %s missing message", rule.rule_id)
			}
			switch rule.match_kind {
			case "Substring", "Regex", "AstCommand":
				// Valid
			case:
				return false, fmt.aprintf("Custom rule %s invalid match_kind: %s", rule.rule_id, rule.match_kind)
			}
			switch rule.severity {
			case "Info", "Warning", "High", "Critical":
				// Valid
			case:
				return false, fmt.aprintf("Custom rule %s invalid severity: %s", rule.rule_id, rule.severity)
			}
			if rule.confidence < 0 || rule.confidence > 1 {
				return false, fmt.aprintf("Custom rule %s confidence must be 0-1, got %f", rule.rule_id, rule.confidence)
			}
		}
	}
	
	return true, ""
}

parse_sxs_config :: proc(data: string) -> (SXS_Config, bool) {
	cfg := default_sxs_config()
	
	if strings.trim_space(data) == "" {
		return cfg, true
	}
	
	value, parse_err := json.parse_string(data)
	if parse_err != .None {
		fmt.eprintln("Failed to parse config JSON:", parse_err)
		return cfg, false
	}
	// Don't defer - destroy manually at end to ensure strings are cloned first
	
	#partial switch root in value {
	case json.Object:
		if v, ok := root["use_builtin_rules"]; ok {
			#partial switch b in v {
			case json.Boolean:
				cfg.use_builtin_rules = bool(b)
			}
		}
		if v, ok := root["block_threshold"]; ok {
			#partial switch s in v {
			case json.String:
				cfg.block_threshold = strings.clone(string(s))
			}
		}
		if v, ok := root["ruleset_version"]; ok {
			#partial switch s in v {
			case json.String:
				cfg.ruleset_version = strings.clone(string(s))
			}
		}
		if v, ok := root["allowlist_paths"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch s in elem {
					case json.String:
						append(&cfg.allowlist_paths, strings.clone(string(s)))
					}
				}
			}
		}
		if v, ok := root["allowlist_commands"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch s in elem {
					case json.String:
						append(&cfg.allowlist_commands, strings.clone(string(s)))
					}
				}
			}
		}
		if v, ok := root["rule_overrides"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch obj in elem {
					case json.Object:
						override: Rule_Override
						if id, ok := obj["rule_id"]; ok {
							#partial switch s in id {
							case json.String:
								override.rule_id = strings.clone(string(s))
							}
						}
						if enabled, ok := obj["enabled"]; ok {
							#partial switch b in enabled {
							case json.Boolean:
								override.enabled = bool(b)
							}
						}
						if severity, ok := obj["severity_override"]; ok {
							#partial switch s in severity {
							case json.String:
								override.severity_override = strings.clone(string(s))
							}
						}
						append(&cfg.rule_overrides, override)
					}
				}
			}
		}
		if v, ok := root["custom_rules"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch obj in elem {
					case json.Object:
						rule: Custom_Rule
						if id, ok := obj["rule_id"]; ok {
							#partial switch s in id {
							case json.String:
								rule.rule_id = strings.clone(string(s))
							}
						}
						if enabled, ok := obj["enabled"]; ok {
							#partial switch b in enabled {
							case json.Boolean:
								rule.enabled = bool(b)
							}
						}
						if severity, ok := obj["severity"]; ok {
							#partial switch s in severity {
							case json.String:
								rule.severity = strings.clone(string(s))
							}
						}
						if match_kind, ok := obj["match_kind"]; ok {
							#partial switch s in match_kind {
							case json.String:
								rule.match_kind = strings.clone(string(s))
							}
						}
						if pattern, ok := obj["pattern"]; ok {
							#partial switch s in pattern {
							case json.String:
								rule.pattern = strings.clone(string(s))
							}
						}
						if category, ok := obj["category"]; ok {
							#partial switch s in category {
							case json.String:
								rule.category = strings.clone(string(s))
							}
						}
						if confidence, ok := obj["confidence"]; ok {
							#partial switch n in confidence {
							case json.Float:
								rule.confidence = f32(n)
							case json.Integer:
								rule.confidence = f32(n)
							}
						}
						if phases, ok := obj["phases"]; ok {
							#partial switch arr2 in phases {
							case json.Array:
								for phase in arr2 {
									#partial switch s in phase {
									case json.String:
										append(&rule.phases, strings.clone(string(s)))
									}
								}
							}
						}
						if message, ok := obj["message"]; ok {
							#partial switch s in message {
							case json.String:
								rule.message = strings.clone(string(s))
							}
						}
						if command_name, ok := obj["command_name"]; ok {
							#partial switch s in command_name {
							case json.String:
								rule.command_name = strings.clone(string(s))
							}
						}
						if arg_pattern, ok := obj["arg_pattern"]; ok {
							#partial switch s in arg_pattern {
							case json.String:
								rule.arg_pattern = strings.clone(string(s))
							}
						}
						if suggestion, ok := obj["suggestion"]; ok {
							#partial switch s in suggestion {
							case json.String:
								rule.suggestion = strings.clone(string(s))
							}
						}
						append(&cfg.custom_rules, rule)
					}
				}
			}
		}
	}
	
	// Manually destroy JSON value after all strings are cloned
	json.destroy_value(value)
	
	return cfg, true
}
