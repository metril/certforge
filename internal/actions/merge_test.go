package actions

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Test refs: id "a".."z"; kinds named by prefix b- (batchable) or p- (per grant).
func mref(n string) ActionRef {
	return ActionRef{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(n)), Kind: n}
}

func isB(r ActionRef) bool { return strings.HasPrefix(r.Kind, "b") }

func gid(b byte) uuid.UUID { return uuid.UUID{0: b} }

func TestTail(t *testing.T) {
	in, tail := Tail([]ActionRef{mref("p1"), mref("b1"), mref("p2")}, isB)
	if len(in) != 1 || len(tail) != 2 || tail[0].Kind != "b1" {
		t.Fatalf("%v %v", in, tail)
	}
	in, tail = Tail([]ActionRef{mref("p1")}, isB)
	if len(in) != 1 || tail != nil {
		t.Fatal("no batchable step: all inline")
	}
}

func TestMergeTails(t *testing.T) {
	// Steps of one name share an id; verifyA and verifyB differ.
	wait, restart := mref("b-wait"), mref("b-restart")
	vA, vB := mref("pA"), mref("pB")
	for _, c := range []struct {
		name  string
		tails map[uuid.UUID][]ActionRef
		want  []string
		share []bool
	}{
		{"example", map[uuid.UUID][]ActionRef{gid(1): {wait, restart, vA}, gid(2): {restart, vB}},
			[]string{"b-wait", "b-restart", "pA", "pB"}, []bool{false, true, false, false}},
		{"batchable first", map[uuid.UUID][]ActionRef{gid(1): {restart}, gid(2): {wait, restart}},
			[]string{"b-wait", "b-restart"}, []bool{false, true}},
		{"disjoint inserts at the cursor", map[uuid.UUID][]ActionRef{gid(1): {wait}, gid(2): {restart}},
			[]string{"b-restart", "b-wait"}, []bool{false, false}},
		{"same action twice in one grant", map[uuid.UUID][]ActionRef{gid(1): {restart, restart}, gid(2): {restart}},
			[]string{"b-restart", "b-restart"}, []bool{true, false}},
		{"single", map[uuid.UUID][]ActionRef{gid(1): {wait, restart}},
			[]string{"b-wait", "b-restart"}, []bool{false, false}},
	} {
		got := MergeTails(c.tails, isB)
		var names []string
		var share []bool
		for _, m := range got {
			names = append(names, m.Ref.Kind)
			share = append(share, m.Shared)
		}
		if !slices.Equal(names, c.want) || !slices.Equal(share, c.share) {
			t.Errorf("%s: %v %v, want %v %v", c.name, names, share, c.want, c.share)
		}
	}
	// Each grant keeps its own order and appears once per own step.
	got := MergeTails(map[uuid.UUID][]ActionRef{gid(2): {mref("b-restart"), vB}, gid(1): {mref("b-wait"), mref("b-restart"), vA}}, isB)
	if len(got[1].Grants) != 2 || got[1].Grants[0] != gid(1) {
		t.Fatalf("grants = %v", got[1].Grants)
	}
}
