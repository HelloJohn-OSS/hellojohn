package audit

import "testing"

func TestWithMeta_ClonesMetadataMap(t *testing.T) {
	t.Parallel()

	base := NewEvent(EventLogin, "tenant-a").WithMeta("method", "password")
	next := base.WithMeta("reason", "invalid_password")

	if _, ok := base.Metadata["reason"]; ok {
		t.Fatalf("base event metadata mutated unexpectedly: %+v", base.Metadata)
	}
	if next.Metadata["method"] != "password" {
		t.Fatalf("expected method metadata to be preserved, got %+v", next.Metadata)
	}

	base.Metadata["method"] = "changed"
	if next.Metadata["method"] != "password" {
		t.Fatalf("expected next event metadata to be immutable from base mutations, got %+v", next.Metadata)
	}
}
