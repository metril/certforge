package delivery

import (
	"regexp"
	"fmt"
	"slices"
	"strings"
)

// HookPhases are the valid hook phases.
var HookPhases = []string{"pre_deploy", "post_deploy"}

// HookKinds are the valid hook kinds.
var HookKinds = []string{"exec", "restart"}

// RestartTargetRE matches a restart hook's target: docker:<container> or
// systemd:<unit>.
var RestartTargetRE = regexp.MustCompile(`^(docker|systemd):[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidateHook checks a hook definition. An exec hook's argv[0] must be an
// absolute path: hooks never run through a shell. A restart hook has no argv
// and a docker:/systemd: target. An empty kind means exec.
func ValidateHook(kind, phase, target string, argv []string, timeoutSeconds int) error {
	if kind == "" {
		kind = "exec"
	}
	if !slices.Contains(HookKinds, kind) {
		return &FieldError{"kind", "kind must be exec or restart"}
	}
	if !slices.Contains(HookPhases, phase) {
		return &FieldError{"phase", "phase must be pre_deploy or post_deploy"}
	}
	if kind == "restart" {
		if len(argv) != 0 {
			return &FieldError{"argv", "a restart hook has no argv"}
		}
		if !RestartTargetRE.MatchString(target) {
			return &FieldError{"target", "target must be docker:<container> or systemd:<unit>"}
		}
		if timeoutSeconds < 1 || timeoutSeconds > 3600 {
			return &FieldError{"timeoutSeconds", "timeout must be 1 to 3600 seconds"}
		}
		return nil
	}
	if target != "" {
		return &FieldError{"target", "target is only for restart hooks"}
	}
	if len(argv) == 0 || len(argv) > 64 {
		return &FieldError{"argv", "argv has 1 to 64 entries"}
	}
	if err := CleanPath("argv[0]", argv[0]); err != nil {
		return &FieldError{"argv[0]", "must be the absolute path of the executable; hooks never run through a shell"}
	}
	for i, a := range argv {
		if strings.ContainsRune(a, 0) || len(a) > 4096 {
			return &FieldError{fmt.Sprintf("argv[%d]", i), "arguments are at most 4096 bytes without NUL"}
		}
	}
	if timeoutSeconds < 1 || timeoutSeconds > 3600 {
		return &FieldError{"timeoutSeconds", "timeout must be 1 to 3600 seconds"}
	}
	return nil
}
