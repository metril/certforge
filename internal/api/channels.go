package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/notify"
)

// errAllOrgsNeedsAdmin is CreateChannel/UpdateChannel's 403 when a
// non-global-admin submits allOrgs true (Shared contract, Channel
// operations row).
var errAllOrgsNeedsAdmin = &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "all-orgs channels need a global admin"}

// mapNotifyErr turns a notify domain error into a problem response.
// notify.ErrChannelNotFound needs id to build a message naming the
// resource, the same way every other resource's not-found path does.
func mapNotifyErr(err error, id uuid.UUID) error {
	var ve *notify.ValidationError
	var ce *notify.ConflictError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, notify.ErrChannelNotFound):
		return notFound("channel %s", id)
	case errors.As(err, &ve):
		return unprocessable(ve.Field, ve.Msg)
	case errors.As(err, &ce):
		return conflict("%s", ce.Msg)
	}
	return err
}

// channelOut maps a notify.Channel to its API shape.
func channelOut(c notify.Channel) gen.Channel {
	events := make([]gen.EventKind, 0, len(c.Events))
	for _, k := range c.Events {
		events = append(events, gen.EventKind(k))
	}
	storedSecrets := c.StoredSecrets
	if storedSecrets == nil {
		storedSecrets = []string{}
	}
	cfg := c.Config
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	var last *gen.ChannelLastDelivery
	if c.LastDelivery != nil {
		ld := gen.ChannelLastDelivery{Status: gen.DeliveryStatus(c.LastDelivery.Status), At: c.LastDelivery.At}
		if c.LastDelivery.Error != "" {
			ld.Error = ptr(c.LastDelivery.Error)
		}
		last = &ld
	}
	return gen.Channel{
		Id: c.ID, OrgId: c.OrgID, Name: c.Name, Type: gen.ChannelType(c.Type), Config: cfg,
		StoredSecrets: storedSecrets, Summary: c.Summary, Events: events, MinSeverity: gen.Severity(c.MinSeverity),
		AllOrgs: c.AllOrgs, Enabled: c.Enabled, LastDelivery: last, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

// toChannelInput converts a ChannelInput request body, applying its own
// defaults (Shared contract: ChannelInput schema).
func toChannelInput(body *gen.ChannelInput) (notify.ChannelInput, error) {
	if body == nil {
		return notify.ChannelInput{}, badRequest("missing body")
	}
	events := []string{}
	if body.Events != nil {
		for _, k := range *body.Events {
			events = append(events, string(k))
		}
	}
	minSeverity := "info"
	if body.MinSeverity != nil {
		minSeverity = string(*body.MinSeverity)
	}
	allOrgs := false
	if body.AllOrgs != nil {
		allOrgs = *body.AllOrgs
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	return notify.ChannelInput{Name: body.Name, Type: string(body.Type), Config: body.Config,
		Events: events, MinSeverity: minSeverity, AllOrgs: allOrgs, Enabled: enabled}, nil
}

// checkAllOrgsGate refuses a caller without global authz:settings-write
// from submitting an all-orgs channel (Shared contract's 403; the check
// applies to every create or update where the submitted value is true,
// whether or not it was already true).
func checkAllOrgsGate(ctx context.Context, allOrgs bool) error {
	if !allOrgs {
		return nil
	}
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return errUnauthenticated
	}
	if !authz.Can(p, authz.ActionSettingsWrite, nil) {
		return errAllOrgsNeedsAdmin
	}
	return nil
}

// ListChannels returns an org's channels, plus — only for a global admin
// — every other org's all_orgs channel.
func (s *Server) ListChannels(ctx context.Context, r gen.ListChannelsRequestObject) (gen.ListChannelsResponseObject, error) {
	p, err := authorize(ctx, authz.ActionAlertsRead, &r.OrgId)
	if err != nil {
		return nil, err
	}
	includeAllOrgs := authz.Can(p, authz.ActionSettingsWrite, nil)
	channels, err := s.d.Notify.ListChannels(ctx, r.OrgId, includeAllOrgs)
	if err != nil {
		return nil, mapNotifyErr(err, r.OrgId)
	}
	out := make(gen.ListChannels200JSONResponse, 0, len(channels))
	for _, c := range channels {
		out = append(out, channelOut(c))
	}
	return out, nil
}

// GetChannel returns one channel of the org.
func (s *Server) GetChannel(ctx context.Context, r gen.GetChannelRequestObject) (gen.GetChannelResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Notify.GetChannel(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapNotifyErr(err, r.Id)
	}
	return gen.GetChannel200JSONResponse(channelOut(c)), nil
}

// CreateChannel adds a notification channel.
func (s *Server) CreateChannel(ctx context.Context, r gen.CreateChannelRequestObject) (gen.CreateChannelResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in, err := toChannelInput(r.Body)
	if err != nil {
		return nil, err
	}
	if err := checkAllOrgsGate(ctx, in.AllOrgs); err != nil {
		return nil, err
	}
	c, err := s.d.Notify.CreateChannel(ctx, r.OrgId, in)
	if err != nil {
		return nil, mapNotifyErr(err, r.OrgId)
	}
	return gen.CreateChannel201JSONResponse(channelOut(c)), nil
}

// UpdateChannel replaces a channel's name, config, events, minSeverity,
// allOrgs and enabled; type is immutable (422 "type cannot change").
func (s *Server) UpdateChannel(ctx context.Context, r gen.UpdateChannelRequestObject) (gen.UpdateChannelResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in, err := toChannelInput(r.Body)
	if err != nil {
		return nil, err
	}
	if err := checkAllOrgsGate(ctx, in.AllOrgs); err != nil {
		return nil, err
	}
	cur, err := s.d.Notify.GetChannel(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapNotifyErr(err, r.Id)
	}
	if in.Type != cur.Type {
		return nil, unprocessable("type", "type cannot change")
	}
	c, err := s.d.Notify.UpdateChannel(ctx, r.OrgId, r.Id, in)
	if err != nil {
		return nil, mapNotifyErr(err, r.Id)
	}
	return gen.UpdateChannel200JSONResponse(channelOut(c)), nil
}

// DeleteChannel removes a channel.
func (s *Server) DeleteChannel(ctx context.Context, r gen.DeleteChannelRequestObject) (gen.DeleteChannelResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Notify.DeleteChannel(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapNotifyErr(err, r.Id)
	}
	return gen.DeleteChannel204Response{}, nil
}

// TestChannel sends a test event to this channel only, inline, bound to
// 10s; allowed whether or not the channel is enabled.
func (s *Server) TestChannel(ctx context.Context, r gen.TestChannelRequestObject) (gen.TestChannelResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	res, err := s.d.Notify.Test(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapNotifyErr(err, r.Id)
	}
	out := gen.DeliveryResult{Status: gen.DeliveryStatus(res.Status), DurationMs: int(res.Duration.Milliseconds())}
	if res.Error != "" {
		out.Error = ptr(res.Error)
	}
	return gen.TestChannel200JSONResponse(out), nil
}
