package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/backup"
)

// abortingReader wraps r so a mid-stream read error panics with
// http.ErrAbortHandler instead of returning to
// gen.CreateBackup200ApplicationoctetStreamResponse's io.Copy (task-12
// brief): createBackup streams with no buffering, so a Stream failure
// after the 200 and headers are already on the wire cannot be reported as
// a JSON error body — recoverer (router.go) re-panics ErrAbortHandler,
// which aborts the connection outright and leaves the client with a
// truncated stream (TestCreateBackupMidStreamErrorAborts), never a
// silently short 200.
type abortingReader struct {
	r io.Reader
}

func (a abortingReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if err != nil && err != io.EOF {
		panic(http.ErrAbortHandler)
	}
	return n, err
}

// Close lets gen's Visit function's io.ReadCloser check close the
// underlying pipe reader once the copy is done (harmless if it already
// hit EOF); a is not itself an io.PipeReader so this must be forwarded.
func (a abortingReader) Close() error {
	if c, ok := a.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// firstLine returns the first line of s, cut to at most n bytes.
func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// CreateBackup streams one on-demand backup archive with no buffering to
// disk or memory: Stream writes straight into an io.Pipe fed to the
// response body. Needs settings:write. Once the whole stream completes successfully,
// backup.created {sizeBytes} is audited (as the requesting principal) and
// the shared status row's LastSuccessAt/LastSizeBytes move (LastFile is
// left alone: an on-demand backup is never written to disk).
func (s *Server) CreateBackup(ctx context.Context, _ gen.CreateBackupRequestObject) (gen.CreateBackupResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		summary, err := s.d.Backup.Stream(ctx, pw)
		if err != nil {
			// A Stream error otherwise only reaches the client as a
			// truncated connection (abortingReader's panic; net/http
			// silences an ErrAbortHandler panic entirely, no log of its
			// own) — logged here so a failed on-demand backup leaves a
			// server-side trace (batch-4 review). Write's own errors never
			// embed key material or other secrets (wrapped fmt.Errorf
			// around table names, SQL errors and I/O failures only), so
			// this needs no separate redaction step.
			s.d.Log.Error("backup: on-demand stream failed", "err", err)
			// WithoutCancel: the request context is usually already
			// cancelled when the stream fails. The shared status row is not
			// touched; scheduled-backup state stays authoritative.
			details := map[string]any{"trigger": "on_demand", "error": firstLine(err.Error(), 200)}
			if errors.Is(err, io.ErrClosedPipe) || ctx.Err() != nil {
				details["reason"] = "client_aborted"
			}
			s.audit(context.WithoutCancel(ctx), audit.Event{Action: "backup.failed", ResourceType: "backup", Details: details})
			_ = pw.CloseWithError(err)
			return
		}
		// The audit row and status update happen before pw.Close(): closing
		// the pipe is what lets the reader's Read return io.EOF, so the
		// client (and the response's own io.Copy) can observe "the stream
		// is complete" before this write is guaranteed to be visible.
		// Doing it after Close would race the client's own read of a fully
		// drained body against these two writes actually committing.
		s.audit(ctx, audit.Event{Action: "backup.created", ResourceType: "backup",
			Details: map[string]any{"sizeBytes": summary.SizeBytes}})
		if err := s.d.Backup.RecordOnDemandSuccess(ctx, summary.SizeBytes); err != nil {
			s.d.Log.Error("backup: record on-demand success failed", "err", err)
		}
		_ = pw.Close()
	}()

	filename := fmt.Sprintf("certforge-%s.cfbak", time.Now().UTC().Format("20060102T150405Z"))
	return gen.CreateBackup200ApplicationoctetStreamResponse{
		Body: abortingReader{r: pr},
		Headers: gen.CreateBackup200ResponseHeaders{
			ContentDisposition: fmt.Sprintf(`attachment; filename="%s"`, filename),
		},
	}, nil
}

// GetBackupStatus reports the configured schedule and the most recent
// backup outcome. Needs settings:read.
func (s *Server) GetBackupStatus(ctx context.Context, _ gen.GetBackupStatusRequestObject) (gen.GetBackupStatusResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsRead, nil); err != nil {
		return nil, err
	}
	st, err := s.d.Backup.Status(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetBackupStatus200JSONResponse(backupStatusToGen(st)), nil
}

// nonEmpty returns nil for "", else a pointer to s — BackupStatus's
// nullable string fields (directory, lastError, lastFile) are all "empty
// means null" in backup.Status.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// backupStatusToGen converts backup.Status to the wire shape: backup is
// kept independent of internal/api/gen (crypto.TransitAPI's doc comment
// explains the same pattern), so the mapping happens here (same
// convention as keys.go's keysStatusToGen).
func backupStatusToGen(st backup.Status) gen.BackupStatus {
	return gen.BackupStatus{
		Schedule:      gen.BackupSchedule(st.Schedule),
		Directory:     nonEmpty(st.Directory),
		LastSuccessAt: st.LastSuccessAt,
		LastFailureAt: st.LastFailureAt,
		LastError:     nonEmpty(st.LastError),
		LastSizeBytes: st.LastSizeBytes,
		LastFile:      nonEmpty(st.LastFile),
		NextAt:        st.NextAt,
	}
}
