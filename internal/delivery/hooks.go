package delivery

import (
	"fmt"
	"slices"
	"strings"
)

// HookPhases are the valid hook phases.
var HookPhases = []string{"pre_deploy", "post_deploy"}

// ValidateHook checks a hook definition. argv[0] must be an absolute path:
// hooks never run through a shell.
func ValidateHook(phase string, argv []string, timeoutSeconds int) error {
	if !slices.Contains(HookPhases, phase) {
		return &FieldError{"phase", "phase must be pre_deploy or post_deploy"}
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
