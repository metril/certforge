//go:build integration

package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify"
)

// insertEvent inserts a notification_events row directly (bypassing
// Emit/MatchingChannels — this package tests listEvents' own read path,
// not the emitter) and backdates its at column, returning the row's id.
func (f *notifyFixture) insertEvent(t *testing.T, orgID *uuid.UUID, kind, severity, dedupe string, at time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id, err := f.q.InsertNotificationEvent(ctx, sqlcgen.InsertNotificationEventParams{
		OrgID: orgID, Kind: kind, Severity: severity, ResourceType: notify.ResourceTypeOf(kind),
		ResourceID: "r1", ResourceName: "r1", Summary: "s", Details: []byte(`{}`), DedupeKey: dedupe})
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE notification_events SET at = $2 WHERE id = $1`, id, at); err != nil {
		t.Fatalf("backdate event: %v", err)
	}
	return id
}

// TestListEventsFiltersAndCursor covers kind, severity (a minimum) and
// since filters at the API layer, plus deliveries[] joining a channel's
// name; cursor/keyset pagination itself is exercised directly against
// notify.Service (the API never exposes a page-size parameter to control
// from an httptest-sized fixture).
func TestListEventsFiltersAndCursor(t *testing.T) {
	f := newNotifyFixture(t)
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)

	issued := f.insertEvent(t, &f.org, "cert.issued", "info", "d1-"+uuid.NewString(), base)
	expired := f.insertEvent(t, &f.org, "cert.expired", "critical", "d2-"+uuid.NewString(), base.Add(time.Minute))
	f.insertEvent(t, &f.org, "monitor.recovered", "info", "d3-"+uuid.NewString(), base.Add(2*time.Minute))
	// A global event (org_id NULL) must also appear on this org's feed.
	backup := f.insertEvent(t, nil, "backup.completed", "info", "d4-"+uuid.NewString(), base.Add(3*time.Minute))
	// Another org's event must never appear.
	otherOrg := dbtest.Org(t, f.pool)
	f.insertEvent(t, &otherOrg, "cert.issued", "info", "d5-"+uuid.NewString(), base.Add(4*time.Minute))

	// A delivery row on the "cert.issued" event, to check deliveries[].
	chRes, err := f.srv.CreateChannel(f.as("operator"), gen.CreateChannelRequestObject{OrgId: f.org, Body: webhookInput("wh", "https://hooks.example.test/x")})
	if err != nil {
		t.Fatal(err)
	}
	channelID := chRes.(gen.CreateChannel201JSONResponse).Id
	if err := f.q.InsertNotificationDelivery(context.Background(), sqlcgen.InsertNotificationDeliveryParams{EventID: issued, ChannelID: channelID}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.MarkNotificationDeliveryDelivered(context.Background(), sqlcgen.MarkNotificationDeliveryDeliveredParams{EventID: issued, ChannelID: channelID, Attempts: 1}); err != nil {
		t.Fatal(err)
	}

	// No filter: every org event plus the global one, newest first.
	res, err := f.srv.ListEvents(f.as("viewer"), gen.ListEventsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	page := res.(gen.ListEvents200JSONResponse)
	if len(page.Items) != 4 {
		t.Fatalf("unfiltered items = %d, want 4", len(page.Items))
	}
	if page.Items[0].Id != backup {
		t.Errorf("first item = %s, want the newest (backup.completed)", page.Items[0].Id)
	}

	// deliveries[] on the cert.issued event.
	var issuedEvent *gen.Event
	for i := range page.Items {
		if page.Items[i].Id == issued {
			issuedEvent = &page.Items[i]
		}
	}
	if issuedEvent == nil {
		t.Fatal("cert.issued event missing from the page")
	}
	if len(issuedEvent.Deliveries) != 1 || issuedEvent.Deliveries[0].ChannelId != channelID ||
		issuedEvent.Deliveries[0].ChannelName != "wh" || issuedEvent.Deliveries[0].Status != gen.DeliveryStatusDelivered {
		t.Fatalf("deliveries = %+v", issuedEvent.Deliveries)
	}

	// kind filter.
	kinds := gen.EventKindFilter{gen.CertIssued}
	res, err = f.srv.ListEvents(f.as("viewer"), gen.ListEventsRequestObject{OrgId: f.org, Params: gen.ListEventsParams{Kind: &kinds}})
	if err != nil {
		t.Fatal(err)
	}
	if items := res.(gen.ListEvents200JSONResponse).Items; len(items) != 1 || items[0].Id != issued {
		t.Fatalf("kind filter items = %+v, want just cert.issued", items)
	}

	// severity filter: minimum critical excludes info events.
	sev := gen.Critical
	res, err = f.srv.ListEvents(f.as("viewer"), gen.ListEventsRequestObject{OrgId: f.org, Params: gen.ListEventsParams{Severity: &sev}})
	if err != nil {
		t.Fatal(err)
	}
	if items := res.(gen.ListEvents200JSONResponse).Items; len(items) != 1 || items[0].Id != expired {
		t.Fatalf("severity filter items = %+v, want just cert.expired", items)
	}

	// since filter.
	since := base.Add(90 * time.Second)
	res, err = f.srv.ListEvents(f.as("viewer"), gen.ListEventsRequestObject{OrgId: f.org, Params: gen.ListEventsParams{Since: &since}})
	if err != nil {
		t.Fatal(err)
	}
	if items := res.(gen.ListEvents200JSONResponse).Items; len(items) != 2 {
		t.Fatalf("since filter items = %d, want 2 (monitor.recovered and backup.completed)", len(items))
	}

	// Unknown-cursor rejection (opaque to the caller).
	badCursor := "not-a-real-cursor"
	_, err = f.srv.ListEvents(f.as("viewer"), gen.ListEventsRequestObject{OrgId: f.org, Params: gen.ListEventsParams{Cursor: &badCursor}})
	wantStatus(t, err, 422)

	// Keyset pagination itself, directly against the service (the API
	// exposes no page-size parameter): a 2-item page, then the cursor
	// exhausts the remaining 2 with no overlap and no duplicate.
	firstPage, err := f.srv.d.Notify.ListEvents(context.Background(), f.org, notify.EventFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Items) != 2 || firstPage.NextCursor == "" {
		t.Fatalf("first page = %+v", firstPage)
	}
	secondPage, err := f.srv.d.Notify.ListEvents(context.Background(), f.org, notify.EventFilter{Limit: 2, Cursor: firstPage.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Items) != 2 || secondPage.NextCursor != "" {
		t.Fatalf("second page = %+v", secondPage)
	}
	seen := map[uuid.UUID]bool{}
	for _, e := range append(firstPage.Items, secondPage.Items...) {
		if seen[e.ID] {
			t.Fatalf("event %s appeared on more than one page", e.ID)
		}
		seen[e.ID] = true
	}
	if len(seen) != 4 {
		t.Fatalf("paginated through %d distinct events, want 4", len(seen))
	}
}
