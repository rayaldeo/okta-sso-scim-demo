// Command vulngate fails CI on reachable vulnerabilities that haven't been
// reviewed. It reads `govulncheck -format json` output on stdin and a list
// of reviewed IDs (see .github/govulncheck-reviewed.txt).
//
//	govulncheck -format json ./... | go run ./tools/vulngate .github/govulncheck-reviewed.txt
//
// Only findings at function level count: govulncheck's own text mode treats
// those as "your code is affected". Reviewed IDs are reported but don't fail
// the build; reviewed IDs that no longer appear are flagged for cleanup.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type message struct {
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: govulncheck -format json ./... | vulngate REVIEWED_FILE")
		os.Exit(2)
	}
	reviewed, err := readReviewed(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "vulngate:", err)
		os.Exit(2)
	}
	found, err := reachable(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vulngate:", err)
		os.Exit(2)
	}
	os.Exit(report(os.Stdout, found, reviewed))
}

// reachable returns the IDs of vulnerabilities whose vulnerable function is
// called from this module.
func reachable(r io.Reader) (map[string]bool, error) {
	found := map[string]bool{}
	dec := json.NewDecoder(r)
	for {
		var m message
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return found, nil
		} else if err != nil {
			return nil, fmt.Errorf("parse govulncheck output: %w", err)
		}
		if m.Finding != nil && len(m.Finding.Trace) > 0 && m.Finding.Trace[0].Function != "" {
			found[m.Finding.OSV] = true
		}
	}
}

func readReviewed(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids[strings.Fields(line)[0]] = true
	}
	return ids, sc.Err()
}

func report(w io.Writer, found, reviewed map[string]bool) int {
	var bad, ok, stale []string
	for id := range found {
		if reviewed[id] {
			ok = append(ok, id)
		} else {
			bad = append(bad, id)
		}
	}
	for id := range reviewed {
		if !found[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(bad)
	sort.Strings(ok)
	sort.Strings(stale)
	for _, id := range ok {
		fmt.Fprintf(w, "reviewed, not affected: %s\n", id)
	}
	for _, id := range stale {
		fmt.Fprintf(w, "no longer reported, remove from the reviewed list: %s\n", id)
	}
	if len(bad) > 0 {
		for _, id := range bad {
			fmt.Fprintf(w, "UNREVIEWED reachable vulnerability: %s (https://pkg.go.dev/vuln/%s)\n", id, id)
		}
		return 1
	}
	fmt.Fprintln(w, "no unreviewed reachable vulnerabilities")
	return 0
}
