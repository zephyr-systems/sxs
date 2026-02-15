package sxs

import "core:encoding/json"
import "core:fmt"
import "core:strings"

Finding :: struct {
	rule_id: string,
	severity: string,
	message: string,
	location: Location,
	suggestion: string,
	phase: string,
	category: string,
	confidence: f32,
	matched_text: string,
	fingerprint: string,
}

Location :: struct {
	file: string,
	line: int,
	column: int,
	length: int,
}

Scan_Result :: struct {
	success: bool,
	blocked: bool,
	findings: [dynamic]Finding,
	errors: [dynamic]string,
	ruleset_version: string,
	stats: Scan_Stats,
}

Scan_Stats :: struct {
	files_scanned: int,
	lines_scanned: int,
	rules_evaluated: int,
	duration_ms: i64,
}

format_result_json :: proc(result: Scan_Result, pretty: bool) -> string {
	opt := json.Marshal_Options{}
	if pretty {
		opt.pretty = true
		opt.use_spaces = true
		opt.spaces = 2
	}
	data, err := json.marshal(result, opt)
	if err != nil {
		err_msg := fmt.aprintf("%v", err)
		builder := strings.builder_make()
		strings.write_string(&builder, `{"success":false,"error":"json_marshal_failed","message":"`)
		strings.write_string(&builder, err_msg)
		strings.write_string(&builder, `"}`)
		return strings.to_string(builder)
	}
	return string(data)
}

format_result_text :: proc(result: Scan_Result, verbose: bool, source: string) -> string {
	builder := strings.builder_make()
	defer strings.builder_destroy(&builder)
	
	if len(result.findings) == 0 {
		strings.write_string(&builder, "No security findings.")
		strings.write_rune(&builder, '\n')
		return strings.to_string(builder)
	}
	
	cyan := "\x1b[36m"
	yellow := "\x1b[33m"
	red := "\x1b[31m"
	magenta := "\x1b[35;1m"
	reset := "\x1b[0m"
	
	critical_count := 0
	high_count := 0
	warning_count := 0
	info_count := 0
	
	for f in result.findings {
		switch f.severity {
		case "Critical":
			critical_count += 1
		case "High":
			high_count += 1
		case "Warning":
			warning_count += 1
		case "Info":
			info_count += 1
		}
	}
	
	strings.write_string(&builder, "Security Scan Results")
	strings.write_rune(&builder, '\n')
	strings.write_string(&builder, "====================")
	strings.write_rune(&builder, '\n')
	strings.write_rune(&builder, '\n')
	
	if source != "" {
		strings.write_string(&builder, "Source: ")
		strings.write_string(&builder, source)
		strings.write_rune(&builder, '\n')
	}
	
	strings.write_string(&builder, "Summary: ")
	printed := false
	if critical_count > 0 {
		strings.write_string(&builder, fmt.aprintf("%d Critical", critical_count))
		printed = true
	}
	if high_count > 0 {
		if printed do strings.write_string(&builder, ", ")
		strings.write_string(&builder, fmt.aprintf("%d High", high_count))
		printed = true
	}
	if warning_count > 0 {
		if printed do strings.write_string(&builder, ", ")
		strings.write_string(&builder, fmt.aprintf("%d Warning", warning_count))
		printed = true
	}
	if info_count > 0 {
		if printed do strings.write_string(&builder, ", ")
		strings.write_string(&builder, fmt.aprintf("%d Info", info_count))
	}
	strings.write_rune(&builder, '\n')
	strings.write_rune(&builder, '\n')
	
	if verbose {
		strings.write_string(&builder, "Findings:")
		strings.write_rune(&builder, '\n')
		strings.write_string(&builder, "---------")
		strings.write_rune(&builder, '\n')
	}
	
	for f in result.findings {
		color := ""
		switch f.severity {
		case "Critical":
			color = magenta
		case "High":
			color = red
		case "Warning":
			color = yellow
		case "Info":
			color = cyan
		}
		
		if verbose {
			strings.write_string(&builder, color)
			strings.write_rune(&builder, '[')
			strings.write_string(&builder, f.severity)
			strings.write_rune(&builder, ']')
			strings.write_string(&builder, reset)
			strings.write_rune(&builder, ' ')
			strings.write_string(&builder, f.rule_id)
			strings.write_rune(&builder, '\n')
			
			strings.write_string(&builder, "  Location: ")
			strings.write_string(&builder, f.location.file)
			strings.write_rune(&builder, ':')
			strings.write_string(&builder, fmt.aprintf("%d", f.location.line))
			strings.write_rune(&builder, '\n')
			
			strings.write_string(&builder, "  Message: ")
			strings.write_string(&builder, f.message)
			strings.write_rune(&builder, '\n')
			
			if f.suggestion != "" {
				strings.write_string(&builder, "  Suggestion: ")
				strings.write_string(&builder, f.suggestion)
				strings.write_rune(&builder, '\n')
			}
			
			strings.write_string(&builder, "  Category: ")
			strings.write_string(&builder, f.category)
			strings.write_rune(&builder, '\n')
			
			strings.write_string(&builder, "  Confidence: ")
			strings.write_string(&builder, fmt.aprintf("%.0f%%", f.confidence * 100))
			strings.write_rune(&builder, '\n')
			
			strings.write_string(&builder, "  Phase: ")
			strings.write_string(&builder, f.phase)
			strings.write_rune(&builder, '\n')
			
			strings.write_rune(&builder, '\n')
		} else {
			strings.write_string(&builder, color)
			strings.write_string(&builder, f.severity)
			strings.write_string(&builder, reset)
			strings.write_string(&builder, " | ")
			strings.write_string(&builder, f.rule_id)
			strings.write_string(&builder, " | ")
			strings.write_string(&builder, f.location.file)
			strings.write_rune(&builder, ':')
			strings.write_string(&builder, fmt.aprintf("%d", f.location.line))
			strings.write_string(&builder, " | ")
			strings.write_string(&builder, f.message)
			strings.write_rune(&builder, '\n')
		}
	}
	
	return strings.to_string(builder)
}

format_result_sarif :: proc(result: Scan_Result, source: string) -> string {
	builder := strings.builder_make()
	defer strings.builder_destroy(&builder)
	
	nl := "\n"
	tb := "\t"
	
	strings.write_string(&builder, "{")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `  "version": "2.1.0",`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `  "runs": [`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "    {")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `      "tool": {`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `        "driver": {`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `          "name": "SXS",`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `          "informationUri": "https://github.com/shellx/sxs",`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `          "version": "`)
	strings.write_string(&builder, VERSION)
	strings.write_string(&builder, `",`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, `          "rules": []`)
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "        }")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "      },")
	strings.write_string(&builder, nl)
	
	strings.write_string(&builder, `      "results": [`)
	strings.write_string(&builder, nl)
	
	for f, i in result.findings {
		if i > 0 {
			strings.write_string(&builder, ",")
			strings.write_string(&builder, nl)
		}
		strings.write_string(&builder, "        {")
		strings.write_string(&builder, nl)
		
		strings.write_string(&builder, `          "ruleId": "`)
		strings.write_string(&builder, escape_json_string(f.rule_id))
		strings.write_string(&builder, `",`)
		strings.write_string(&builder, nl)
		
		level := "warning"
		if f.severity == "Critical" || f.severity == "High" {
			level = "error"
		} else if f.severity == "Info" {
			level = "note"
		}
		strings.write_string(&builder, `          "level": "`)
		strings.write_string(&builder, level)
		strings.write_string(&builder, `",`)
		strings.write_string(&builder, nl)
		
		strings.write_string(&builder, `          "message": {`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `            "text": "`)
		strings.write_string(&builder, escape_json_string(f.message))
		strings.write_string(&builder, `"`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "          },")
		strings.write_string(&builder, nl)
		
		strings.write_string(&builder, `          "locations": [`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "            {")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `              "physicalLocation": {`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                "artifactLocation": {`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                  "uri": "`)
		strings.write_string(&builder, escape_json_string(f.location.file))
		strings.write_string(&builder, `"`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "                },")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                "region": {`)
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                  "startLine": `)
		strings.write_string(&builder, fmt.aprintf("%d", f.location.line))
		strings.write_string(&builder, ",")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                  "startColumn": `)
		strings.write_string(&builder, fmt.aprintf("%d", f.location.column + 1))
		strings.write_string(&builder, ",")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, `                  "byteLength": `)
		strings.write_string(&builder, fmt.aprintf("%d", f.location.length))
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "                }")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "              }")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "            }")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "          ]")
		strings.write_string(&builder, nl)
		strings.write_string(&builder, "        }")
	}
	
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "        ]")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "    }")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "  ]")
	strings.write_string(&builder, nl)
	strings.write_string(&builder, "}")
	strings.write_string(&builder, nl)
	
	return strings.to_string(builder)
}

escape_json_string :: proc(s: string) -> string {
	result := strings.builder_make()
	defer strings.builder_destroy(&result)
	
	for ch in s {
		switch ch {
		case '"':
			strings.write_string(&result, "\\\"")
		case '\\':
			strings.write_string(&result, "\\\\")
		case '\n':
			strings.write_string(&result, "\\n")
		case '\r':
			strings.write_string(&result, "\\r")
		case '\t':
			strings.write_string(&result, "\\t")
		case:
			strings.write_rune(&result, ch)
		}
	}
	
	return strings.to_string(result)
}
