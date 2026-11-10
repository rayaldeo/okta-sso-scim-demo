package main

import (
	"bytes"
	"strings"
	"testing"
)

// A trimmed govulncheck -format json stream: one called (function-level)
// finding and one module-level finding that isn't reachable.
const stream = `
{"config": {"protocol_version": "v1.0.0"}}
{"finding": {"osv": "GO-2026-0001", "trace": [{"module": "m", "package": "p", "function": "F"}]}}
{"finding": {"osv": "GO-2026-0002", "trace": [{"module": "m"}]}}
`

func TestOnlyCalledVulnsCount(t *testing.T) {
	found, err := reachable(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if !found["GO-2026-0001"] || found["GO-2026-0002"] || len(found) != 1 {
		t.Fatalf("got %v", found)
	}
}

func TestUnreviewedFails(t *testing.T) {
	var out bytes.Buffer
	if code := report(&out, map[string]bool{"GO-1": true}, map[string]bool{}); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "UNREVIEWED reachable vulnerability: GO-1") {
		t.Fatal(out.String())
	}
}

func TestReviewedPassesAndStaleIsFlagged(t *testing.T) {
	var out bytes.Buffer
	code := report(&out, map[string]bool{"GO-1": true}, map[string]bool{"GO-1": true, "GO-OLD": true})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "remove from the reviewed list: GO-OLD") {
		t.Fatal(out.String())
	}
}
