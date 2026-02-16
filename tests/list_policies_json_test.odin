package tests

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:os/os2"
import "core:strings"
import "core:testing"

DEFAULT_SXS_RUNNER :: "/Users/z3robit/Development/odin/sxs/run"
DEFAULT_SXS_ROOT :: "/Users/z3robit/Development/odin/sxs"

resolve_sxs_runner :: proc() -> string {
	if v := strings.trim_space(os.get_env("SXS_CLI_BIN")); v != "" {
		return v
	}
	return DEFAULT_SXS_RUNNER
}

@(test)
test_list_policies_json_schema_stability :: proc(t: ^testing.T) {
	build_cmd := []string{"make", "-C", DEFAULT_SXS_ROOT, "build"}
	build_state, build_out, build_err_out, build_err := os2.process_exec(
		os2.Process_Desc{command = build_cmd[:]},
		context.allocator,
	)
	defer delete(build_out)
	defer delete(build_err_out)
	testing.expect(t, build_err == nil, "sxs build command should execute before schema test")
	testing.expect(t, build_state.exit_code == 0, "sxs build should succeed before schema test")
	if build_err != nil || build_state.exit_code != 0 {
		return
	}

	runner := resolve_sxs_runner()
	cmd := []string{runner, "--list-policies", "--format", "json"}
	state, out, err_out, err := os2.process_exec(
		os2.Process_Desc{command = cmd[:]},
		context.allocator,
	)
	defer {
		delete(out)
		delete(err_out)
	}

	testing.expect(t, err == nil, "list-policies json command should execute")
	testing.expect(t, state.exit_code == 0, "list-policies json command should exit 0")
	if err != nil || state.exit_code != 0 {
		return
	}

	raw := string(out)
	value, parse_err := json.parse_string(raw)
	testing.expect(t, parse_err == .None, "list-policies output should be valid JSON")
	if parse_err != .None {
		return
	}
	defer json.destroy_value(value)

	root, ok := value.(json.Object)
	testing.expect(t, ok, "list-policies output root should be JSON object")
	if !ok {
		return
	}

	expect_string_field :: proc(
		t: ^testing.T,
		obj: json.Object,
		key: string,
		message: string,
	) -> bool {
		v, exists := obj[key]
		testing.expect(t, exists, message)
		if !exists {
			return false
		}
		_, is_string := v.(json.String)
		testing.expect(t, is_string, message)
		return is_string
	}

	expect_number_field :: proc(
		t: ^testing.T,
		obj: json.Object,
		key: string,
		message: string,
	) -> bool {
		v, exists := obj[key]
		testing.expect(t, exists, message)
		if !exists {
			return false
		}
		_, is_int := v.(json.Integer)
		if is_int {
			return true
		}
		_, is_float := v.(json.Float)
		testing.expect(t, is_float, message)
		return is_float
	}

	if !expect_string_field(t, root, "command", "list-policies JSON should contain string field `command`") {
		return
	}
	if !expect_string_field(t, root, "schema_version", "list-policies JSON should contain string field `schema_version`") {
		return
	}
	if !expect_number_field(t, root, "total_policies", "list-policies JSON should contain numeric field `total_policies`") {
		return
	}

	counts_v, ok_counts := root["counts"]
	testing.expect(t, ok_counts, "list-policies JSON should contain object field `counts`")
	if !ok_counts {
		return
	}
	counts, ok_obj := counts_v.(json.Object)
	testing.expect(t, ok_obj, "list-policies `counts` should be JSON object")
	if !ok_obj {
		return
	}
	if !expect_number_field(t, counts, "active", "list-policies counts should include numeric `active`") {
		return
	}
	if !expect_number_field(t, counts, "valid", "list-policies counts should include numeric `valid`") {
		return
	}

	policies_v, ok_policies := root["policies"]
	testing.expect(t, ok_policies, "list-policies JSON should contain array field `policies`")
	if !ok_policies {
		return
	}
	policies, ok_arr := policies_v.(json.Array)
	testing.expect(t, ok_arr, "list-policies `policies` should be JSON array")
	if !ok_arr || len(policies) == 0 {
		testing.expect(t, len(policies) > 0, "list-policies JSON should include at least one policy")
		return
	}

	first, ok_first := policies[0].(json.Object)
	testing.expect(t, ok_first, "first policy entry should be JSON object")
	if !ok_first {
		return
	}

	expect_string_field(t, first, "name", "policy entry should include string `name`")
	expect_string_field(t, first, "type", "policy entry should include string `type`")
	expect_string_field(t, first, "source", "policy entry should include string `source`")
	expect_string_field(t, first, "description", "policy entry should include string `description`")

	active_v, has_active := first["active"]
	testing.expect(t, has_active, "policy entry should include boolean `active`")
	if has_active {
		_, is_bool := active_v.(json.Boolean)
		testing.expect(t, is_bool, "policy entry field `active` should be boolean")
	}
	valid_v, has_valid := first["valid"]
	testing.expect(t, has_valid, "policy entry should include boolean `valid`")
	if has_valid {
		_, is_bool := valid_v.(json.Boolean)
		testing.expect(t, is_bool, "policy entry field `valid` should be boolean")
	}

	if sv, ok := root["schema_version"]; ok {
		#partial switch s in sv {
		case json.String:
			testing.expect(t, strings.trim_space(string(s)) != "", "schema_version should be non-empty")
		}
	}

	fmt.println("✓ Test: --list-policies --format json schema stability")
}
