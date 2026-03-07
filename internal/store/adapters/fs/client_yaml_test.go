package fs

import "testing"

func TestClientYAMLToRepositoryDefaultsAuthProfile(t *testing.T) {
	t.Parallel()

	c := clientYAML{
		ClientID: "web-app",
		Name:     "Web App",
		Type:     "public",
	}

	got := c.toRepository("tenant-a")
	if got.AuthProfile != "spa" {
		t.Fatalf("expected default auth profile spa, got=%q", got.AuthProfile)
	}
}
