package api

import (
	"context"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/notify"
)

// eventOut maps one notify.EventWithDeliveries to its API shape.
func eventOut(e notify.EventWithDeliveries) gen.Event {
	deliveries := make([]gen.EventDelivery, 0, len(e.Deliveries))
	for _, d := range e.Deliveries {
		item := gen.EventDelivery{ChannelId: d.ChannelID, ChannelName: d.ChannelName,
			Status: gen.DeliveryStatus(d.Status), Attempts: d.Attempts, DeliveredAt: d.DeliveredAt}
		if d.LastError != "" {
			item.LastError = ptr(d.LastError)
		}
		deliveries = append(deliveries, item)
	}
	details := e.Details
	if details == nil {
		details = map[string]interface{}{}
	}
	return gen.Event{
		Id: e.ID, Kind: gen.EventKind(e.Kind), At: e.At, OrgId: e.OrgID,
		Resource: gen.EventResource{Type: gen.EventResourceType(e.Resource.Type), Id: e.Resource.ID, Name: e.Resource.Name},
		Severity: gen.Severity(e.Severity), Summary: e.Summary, Details: details, Deliveries: deliveries,
	}
}

// ListEvents returns one page of the org's events (its own, plus every
// global event), newest first.
func (s *Server) ListEvents(ctx context.Context, r gen.ListEventsRequestObject) (gen.ListEventsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	pr := r.Params
	f := notify.EventFilter{}
	if pr.Kind != nil {
		for _, k := range *pr.Kind {
			f.Kinds = append(f.Kinds, string(k))
		}
	}
	if pr.Severity != nil {
		f.MinSeverity = string(*pr.Severity)
	}
	if pr.Since != nil {
		since := *pr.Since
		f.Since = &since
	}
	if pr.Cursor != nil {
		f.Cursor = *pr.Cursor
	}
	page, err := s.d.Notify.ListEvents(ctx, r.OrgId, f)
	if err != nil {
		return nil, mapNotifyErr(err, r.OrgId)
	}
	items := make([]gen.Event, 0, len(page.Items))
	for _, e := range page.Items {
		items = append(items, eventOut(e))
	}
	var next *string
	if page.NextCursor != "" {
		c := page.NextCursor
		next = &c
	}
	return gen.ListEvents200JSONResponse(gen.EventPage{Items: items, NextCursor: next}), nil
}
