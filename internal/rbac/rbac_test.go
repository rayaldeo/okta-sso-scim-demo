package rbac

import "testing"

func TestRoleFor(t *testing.T) {
	m := Mapping{AdminGroup: "app-admin", ViewerGroup: "app-viewer"}
	tests := []struct {
		name   string
		groups []string
		want   Role
	}{
		{"no groups", nil, RoleNone},
		{"unrelated groups", []string{"Everyone", "finance"}, RoleNone},
		{"viewer", []string{"Everyone", "app-viewer"}, RoleViewer},
		{"admin", []string{"app-admin"}, RoleAdmin},
		{"admin wins regardless of order", []string{"app-viewer", "app-admin"}, RoleAdmin},
		{"case-sensitive match", []string{"APP-ADMIN"}, RoleNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.RoleFor(tt.groups); got != tt.want {
				t.Fatalf("RoleFor(%v) = %v, want %v", tt.groups, got, tt.want)
			}
		})
	}
}

func TestSatisfies(t *testing.T) {
	if !RoleAdmin.Satisfies(RoleViewer) {
		t.Error("admin should satisfy viewer")
	}
	if RoleViewer.Satisfies(RoleAdmin) {
		t.Error("viewer must not satisfy admin")
	}
	if RoleNone.Satisfies(RoleViewer) {
		t.Error("none must not satisfy viewer")
	}
}
