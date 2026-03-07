package pg

import (
	"strings"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func normalizeSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func assertContains(t *testing.T, sql, needle string) {
	t.Helper()
	if !strings.Contains(sql, needle) {
		t.Fatalf("expected SQL to contain %q, got: %s", needle, sql)
	}
}

func assertNotContains(t *testing.T, sql, needle string) {
	t.Helper()
	if strings.Contains(sql, needle) {
		t.Fatalf("expected SQL to not contain %q, got: %s", needle, sql)
	}
}

func TestBuildListDeliveriesQuery_TC_R01_NoFilters(t *testing.T) {
	t.Parallel()

	query, args := buildListDeliveriesQuery("wh_123", 25, 0, repository.WebhookDeliveryFilter{})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1")
	assertNotContains(t, norm, "created_at >=")
	assertNotContains(t, norm, "created_at <=")
	assertNotContains(t, norm, "status =")
	assertNotContains(t, norm, "event_type =")
	assertContains(t, norm, "LIMIT $2 OFFSET $3")

	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
	if args[0] != "wh_123" {
		t.Fatalf("expected webhook arg wh_123, got %#v", args[0])
	}
	if args[1] != 26 {
		t.Fatalf("expected limit+1 arg 26, got %#v", args[1])
	}
	if args[2] != 0 {
		t.Fatalf("expected offset arg 0, got %#v", args[2])
	}
}

func TestBuildListDeliveriesQuery_TC_R02_OnlyFrom(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	query, args := buildListDeliveriesQuery("wh_123", 25, 5, repository.WebhookDeliveryFilter{From: from})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND created_at >= $2")
	assertContains(t, norm, "LIMIT $3 OFFSET $4")

	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	gotFrom, ok := args[1].(time.Time)
	if !ok {
		t.Fatalf("expected args[1] to be time.Time, got %T", args[1])
	}
	if !gotFrom.Equal(from) {
		t.Fatalf("expected from arg %s, got %s", from, gotFrom)
	}
}

func TestBuildListDeliveriesQuery_TC_R03_OnlyTo(t *testing.T) {
	t.Parallel()

	to := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	query, args := buildListDeliveriesQuery("wh_123", 25, 0, repository.WebhookDeliveryFilter{To: to})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND created_at <= $2")
	assertContains(t, norm, "LIMIT $3 OFFSET $4")

	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	gotTo, ok := args[1].(time.Time)
	if !ok {
		t.Fatalf("expected args[1] to be time.Time, got %T", args[1])
	}
	if !gotTo.Equal(to) {
		t.Fatalf("expected to arg %s, got %s", to, gotTo)
	}
}

func TestBuildListDeliveriesQuery_TC_R04_FromAndTo(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	query, args := buildListDeliveriesQuery("wh_123", 25, 10, repository.WebhookDeliveryFilter{From: from, To: to})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND created_at >= $2 AND created_at <= $3")
	assertContains(t, norm, "LIMIT $4 OFFSET $5")

	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d", len(args))
	}
}

func TestBuildListDeliveriesQuery_TC_R05_Result(t *testing.T) {
	t.Parallel()

	query, args := buildListDeliveriesQuery("wh_123", 25, 0, repository.WebhookDeliveryFilter{Result: "delivered"})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND status = $2")
	assertContains(t, norm, "LIMIT $3 OFFSET $4")

	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	if args[1] != "delivered" {
		t.Fatalf("expected result arg delivered, got %#v", args[1])
	}
}

func TestBuildListDeliveriesQuery_TC_R06_Event(t *testing.T) {
	t.Parallel()

	query, args := buildListDeliveriesQuery("wh_123", 25, 0, repository.WebhookDeliveryFilter{Event: "user.login"})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND event_type = $2")
	assertContains(t, norm, "LIMIT $3 OFFSET $4")

	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	if args[1] != "user.login" {
		t.Fatalf("expected event arg user.login, got %#v", args[1])
	}
}

func TestBuildListDeliveriesQuery_TC_R07_AllFilters(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	query, args := buildListDeliveriesQuery("wh_123", 25, 20, repository.WebhookDeliveryFilter{
		From:   from,
		To:     to,
		Result: "failed",
		Event:  "system.ping",
	})
	norm := normalizeSQL(query)

	assertContains(t, norm, "WHERE webhook_id = $1 AND created_at >= $2 AND created_at <= $3 AND status = $4 AND event_type = $5")
	assertContains(t, norm, "LIMIT $6 OFFSET $7")

	if len(args) != 7 {
		t.Fatalf("expected 7 args, got %d", len(args))
	}
}

func TestBuildListDeliveriesQuery_TC_R08_UsesLimitPlusOne(t *testing.T) {
	t.Parallel()

	_, args := buildListDeliveriesQuery("wh_123", 50, 0, repository.WebhookDeliveryFilter{})
	if len(args) < 2 {
		t.Fatalf("expected at least 2 args, got %d", len(args))
	}
	if args[len(args)-2] != 51 {
		t.Fatalf("expected limit+1 (51), got %#v", args[len(args)-2])
	}
}
