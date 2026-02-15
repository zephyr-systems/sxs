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

SXS_Config :: struct {
	use_builtin_rules: bool,
	block_threshold: string,
	ruleset_version: string,
	allowlist_paths: [dynamic]string,
	allowlist_commands: [dynamic]string,
	include_rules: [dynamic]string,
}

default_sxs_config :: proc() -> SXS_Config {
	return SXS_Config{
		use_builtin_rules = true,
		block_threshold = "High",
		allowlist_paths = make([dynamic]string),
		allowlist_commands = make([dynamic]string),
		include_rules = make([dynamic]string),
	}
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
	defer json.destroy_value(value)
	
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
				cfg.block_threshold = string(s)
			}
		}
		if v, ok := root["ruleset_version"]; ok {
			#partial switch s in v {
			case json.String:
				cfg.ruleset_version = string(s)
			}
		}
		if v, ok := root["allowlist_paths"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch s in elem {
					case json.String:
						append(&cfg.allowlist_paths, string(s))
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
						append(&cfg.allowlist_commands, string(s))
					}
				}
			}
		}
		if v, ok := root["include_rules"]; ok {
			#partial switch arr in v {
			case json.Array:
				for elem in arr {
					#partial switch s in elem {
					case json.String:
						append(&cfg.include_rules, string(s))
					}
				}
			}
		}
	}
	
	return cfg, true
}
