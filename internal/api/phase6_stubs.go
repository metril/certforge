package api

import (
	"context"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
)

// Phase 6A contract stubs. These operations are declared in api/openapi.yaml
// (Task 2) but not yet implemented; each later task (6: channel and event
// operations; 9: monitor operations; 12: CreateBackup/GetBackupStatus)
// moves its own method out of this file into its resource file and, once
// the last one leaves (Task 14), this file is deleted. TestSmtpSettings
// moved out in Task 5 (internal/api/settings.go). getServerInfo is real
// from Task 2 on (internal/api/server_info.go), not a
// stub here.

var errPhase6NotImplemented = &HTTPError{Status: http.StatusNotImplemented, Title: "Not implemented"}

// ListChannels is implemented in Task 6 (channels and events API).
func (s *Server) ListChannels(context.Context, gen.ListChannelsRequestObject) (gen.ListChannelsResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// CreateChannel is implemented in Task 6 (channels and events API).
func (s *Server) CreateChannel(context.Context, gen.CreateChannelRequestObject) (gen.CreateChannelResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// GetChannel is implemented in Task 6 (channels and events API).
func (s *Server) GetChannel(context.Context, gen.GetChannelRequestObject) (gen.GetChannelResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// UpdateChannel is implemented in Task 6 (channels and events API).
func (s *Server) UpdateChannel(context.Context, gen.UpdateChannelRequestObject) (gen.UpdateChannelResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// DeleteChannel is implemented in Task 6 (channels and events API).
func (s *Server) DeleteChannel(context.Context, gen.DeleteChannelRequestObject) (gen.DeleteChannelResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// TestChannel is implemented in Task 6 (channels and events API).
func (s *Server) TestChannel(context.Context, gen.TestChannelRequestObject) (gen.TestChannelResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// ListEvents is implemented in Task 6 (channels and events API).
func (s *Server) ListEvents(context.Context, gen.ListEventsRequestObject) (gen.ListEventsResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// ListMonitors is implemented in Task 9 (external monitors).
func (s *Server) ListMonitors(context.Context, gen.ListMonitorsRequestObject) (gen.ListMonitorsResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// CreateMonitor is implemented in Task 9 (external monitors).
func (s *Server) CreateMonitor(context.Context, gen.CreateMonitorRequestObject) (gen.CreateMonitorResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// GetMonitor is implemented in Task 9 (external monitors).
func (s *Server) GetMonitor(context.Context, gen.GetMonitorRequestObject) (gen.GetMonitorResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// UpdateMonitor is implemented in Task 9 (external monitors).
func (s *Server) UpdateMonitor(context.Context, gen.UpdateMonitorRequestObject) (gen.UpdateMonitorResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// DeleteMonitor is implemented in Task 9 (external monitors).
func (s *Server) DeleteMonitor(context.Context, gen.DeleteMonitorRequestObject) (gen.DeleteMonitorResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// CheckMonitor is implemented in Task 9 (external monitors).
func (s *Server) CheckMonitor(context.Context, gen.CheckMonitorRequestObject) (gen.CheckMonitorResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// CreateBackup is implemented in Task 12 (backup API, schedule, readiness).
func (s *Server) CreateBackup(context.Context, gen.CreateBackupRequestObject) (gen.CreateBackupResponseObject, error) {
	return nil, errPhase6NotImplemented
}

// GetBackupStatus is implemented in Task 12 (backup API, schedule, readiness).
func (s *Server) GetBackupStatus(context.Context, gen.GetBackupStatusRequestObject) (gen.GetBackupStatusResponseObject, error) {
	return nil, errPhase6NotImplemented
}
