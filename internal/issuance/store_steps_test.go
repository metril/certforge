package issuance

import "testing"

// A nil timeline (no step recorded yet, e.g. a failure before the first step)
// must persist and read back as an empty array, never JSON null: the API
// types steps as a non-null array and the web UI calls .findIndex on it.
func TestStepsJSONNeverNull(t *testing.T) {
	for _, in := range [][]Step{nil, {}} {
		b, err := marshalSteps(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "[]" {
			t.Fatalf("marshalSteps(%#v) = %s, want []", in, b)
		}
	}
	// Rows already stored as null by older builds must read back non-nil.
	got, err := unmarshalSteps([]byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("unmarshalSteps(null) = nil, want empty non-nil slice")
	}
}
