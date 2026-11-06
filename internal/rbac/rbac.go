// Package rbac maps Okta group membership to application roles.
//
// Deny by default: a user in neither mapped group gets RoleNone and can sign
// in but cannot reach any protected page.
package rbac

// Role is an application role. Higher roles include lower ones.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleViewer:
		return "viewer"
	default:
		return "none"
	}
}

// Satisfies reports whether r is at least required.
func (r Role) Satisfies(required Role) bool { return r >= required }

// Mapping names the Okta groups that grant each role.
type Mapping struct {
	AdminGroup  string
	ViewerGroup string
}

// RoleFor returns the highest role granted by groups. Group names are
// matched exactly (case-sensitive), as Okta sends them.
func (m Mapping) RoleFor(groups []string) Role {
	role := RoleNone
	for _, g := range groups {
		switch g {
		case m.AdminGroup:
			return RoleAdmin
		case m.ViewerGroup:
			role = RoleViewer
		}
	}
	return role
}
