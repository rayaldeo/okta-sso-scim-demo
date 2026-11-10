package auth

import (
	"encoding/xml"
	"testing"

	"github.com/crewjam/saml"
)

// GO-2026-6909 describes two flaws in crewjam/saml "through v0.5.1", but
// the advisory's affected range covers every version, so govulncheck flags
// the version we use. These tests pin down that the version in go.mod is
// not affected; if an upgrade regresses either behaviour, they fail.
// See .github/govulncheck-reviewed.txt.

const samlNS = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`

// Flaw 1: a nil *Issuer was dereferenced when an assertion had no Issuer.
// Here Issuer is a value type, so a missing element can't be nil.
func TestGO20266909AssertionWithoutIssuerCannotBeNil(t *testing.T) {
	var a saml.Assertion
	doc := `<saml:Assertion ` + samlNS + ` ID="a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">` +
		`<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>`
	if err := xml.Unmarshal([]byte(doc), &a); err != nil {
		t.Fatal(err)
	}
	if a.Issuer.Value != "" { // compiles only while Issuer is a value, not a pointer
		t.Fatalf("unexpected issuer %q", a.Issuer.Value)
	}
}

// Flaw 2: Subject.NameID matched <NameID> in any namespace, so a foreign
// element could stand in for the real one. It must be ignored.
func TestGO20266909ForeignNamespaceNameIDIsIgnored(t *testing.T) {
	var a saml.Assertion
	doc := `<saml:Assertion ` + samlNS + ` ID="a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.com</saml:Issuer>` +
		`<saml:Subject><x:NameID xmlns:x="urn:example:not-saml">admin@example.com</x:NameID></saml:Subject>` +
		`</saml:Assertion>`
	if err := xml.Unmarshal([]byte(doc), &a); err != nil {
		t.Fatal(err)
	}
	if a.Subject == nil {
		t.Fatal("subject not parsed")
	}
	if a.Subject.NameID != nil {
		t.Fatalf("foreign-namespace NameID was accepted as %q", a.Subject.NameID.Value)
	}
}
