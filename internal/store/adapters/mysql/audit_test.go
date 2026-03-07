package mysql

import (
	"context"
	"errors"
	"testing"
)

func TestSanitizeIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		out  any
	}{
		{name: "empty", in: "", out: nil},
		{name: "ipv4", in: "10.0.0.1", out: "10.0.0.1"},
		{name: "ipv4 with port", in: "10.0.0.1:8080", out: "10.0.0.1"},
		{name: "forwarded chain", in: "10.0.0.1, 10.0.0.2", out: "10.0.0.1"},
		{name: "invalid", in: "not-an-ip", out: nil},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeIP(tc.in)
			if tc.out == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}

			gotStr, ok := got.(string)
			if !ok {
				t.Fatalf("expected string, got %T", got)
			}
			if gotStr != tc.out {
				t.Fatalf("expected %v, got %v", tc.out, gotStr)
			}
		})
	}
}

func TestPurgeInBatches(t *testing.T) {
	t.Parallel()

	t.Run("accumulates until final partial batch", func(t *testing.T) {
		t.Parallel()

		counts := []int64{1000, 1000, 120}
		calls := 0

		total, err := purgeInBatches(context.Background(), 1000, func(ctx context.Context, limit int) (int64, error) {
			if limit != 1000 {
				t.Fatalf("expected batch size 1000, got %d", limit)
			}
			n := counts[calls]
			calls++
			return n, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 2120 {
			t.Fatalf("expected total 2120, got %d", total)
		}
		if calls != 3 {
			t.Fatalf("expected 3 calls, got %d", calls)
		}
	})

	t.Run("returns partial total on error", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("boom")
		calls := 0

		total, err := purgeInBatches(context.Background(), 1000, func(ctx context.Context, limit int) (int64, error) {
			calls++
			if calls == 2 {
				return 0, wantErr
			}
			return 1000, nil
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
		if total != 1000 {
			t.Fatalf("expected partial total 1000, got %d", total)
		}
	})
}
