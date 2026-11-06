package actions

import (
	"bytes"
	"sort"

	"github.com/google/uuid"
)

// IsBatch reports whether ref's kind and config make it batchable.
func IsBatch(ref ActionRef) bool {
	k, ok := Default.Get(ref.Kind)
	return ok && k.Batch(ref.Config)
}

// Tail splits a grant's post steps into the ones that run inline and the
// tail: the first batchable step and everything after it.
func Tail(refs []ActionRef, isBatch func(ActionRef) bool) (inline, tail []ActionRef) {
	for i, r := range refs {
		if isBatch(r) {
			return refs[:i], refs[i:]
		}
	}
	return refs, nil
}

// MergedStep is one step of the merged tail of a host and the grants it runs for.
type MergedStep struct {
	Ref    ActionRef
	Grants []uuid.UUID
	// Shared is true when more than one grant contributes.
	Shared bool
}

// MergeTails merges the tails of grants on one host. Tails are appended in
// grant id order behind a cursor. A batchable step whose action already
// appears at or after the cursor is shared and the cursor moves past it;
// anything else is inserted at the cursor (a per-grant step after the
// per-grant steps already there, before the next batchable one). Each
// grant's own order is kept.
func MergeTails(tails map[uuid.UUID][]ActionRef, isBatch func(ActionRef) bool) []MergedStep {
	ids := make([]uuid.UUID, 0, len(tails))
	for id := range tails {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	var out []MergedStep
	for _, g := range ids {
		cursor := 0
		for _, r := range tails[g] {
			batch := isBatch(r)
			if batch {
				found := -1
				for i := cursor; i < len(out); i++ {
					if out[i].Ref.ID == r.ID && isBatch(out[i].Ref) {
						found = i
						break
					}
				}
				if found >= 0 {
					out[found].Grants = append(out[found].Grants, g)
					out[found].Shared = true
					cursor = found + 1
					continue
				}
			} else {
				for cursor < len(out) && !isBatch(out[cursor].Ref) {
					cursor++
				}
			}
			out = append(out, MergedStep{})
			copy(out[cursor+1:], out[cursor:])
			out[cursor] = MergedStep{Ref: r, Grants: []uuid.UUID{g}}
			cursor++
		}
	}
	return out
}
