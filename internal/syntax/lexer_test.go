package syntax

import "testing"

func TestTokens(t *testing.T) {
	line := `set interfaces ge-0/0/24 vlan members [ USERS "VOICE VLAN" MGMT ]`
	got := Fields(line)
	want := []string{"set", "interfaces", "ge-0/0/24", "vlan", "members", "[", "USERS", "VOICE VLAN", "MGMT", "]"}
	if len(got) != len(want) {
		t.Fatalf("tokens = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}
