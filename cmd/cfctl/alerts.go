package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

// stringSliceFlag accumulates a repeatable flag (--kind, repeated) into a
// slice, in the order given.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	out := ""
	for i, v := range *s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// --- channels ---

func cmdChannels(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl channels: expected a subcommand (list, test)")
		return 2
	}
	switch args[0] {
	case "list":
		return channelsList(ctx, e, args[1:])
	case "test":
		return channelsTest(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl channels: unknown subcommand %q\n", args[0])
		return 2
	}
}

func channelsList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("channels list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.ListChannelsWithResponse(ctx, orgID)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		var rows [][]string
		for _, c := range *resp.JSON200 {
			rows = append(rows, []string{c.Id.String(), c.Name, string(c.Type), fmt.Sprintf("%t", c.Enabled), c.Summary})
		}
		writeTable(e.stdout, []string{"ID", "NAME", "TYPE", "ENABLED", "SUMMARY"}, rows)
	}
	return 0
}

func channelsTest(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("channels test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl channels test: expected exactly one channel id")
		return 2
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid channel id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.TestChannelWithResponse(ctx, orgID, id)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		r := *resp.JSON200
		errStr := ""
		if r.Error != nil {
			errStr = *r.Error
		}
		writeTable(e.stdout, []string{"STATUS", "DURATION_MS", "ERROR"}, [][]string{
			{string(r.Status), fmt.Sprintf("%d", r.DurationMs), errStr},
		})
	}
	return 0
}

// --- monitors ---

func cmdMonitors(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl monitors: expected a subcommand (list, check)")
		return 2
	}
	switch args[0] {
	case "list":
		return monitorsList(ctx, e, args[1:])
	case "check":
		return monitorsCheck(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl monitors: unknown subcommand %q\n", args[0])
		return 2
	}
}

func monitorsList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("monitors list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.ListMonitorsWithResponse(ctx, orgID)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		var rows [][]string
		for _, m := range *resp.JSON200 {
			rows = append(rows, monitorRow(m))
		}
		writeTable(e.stdout, []string{"ID", "NAME", "HOST", "PORT", "STATE"}, rows)
	}
	return 0
}

func monitorRow(m client.Monitor) []string {
	return []string{m.Id.String(), m.Name, m.Host, fmt.Sprintf("%d", m.Port), string(m.State)}
}

func monitorsCheck(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("monitors check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl monitors check: expected exactly one monitor id")
		return 2
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid monitor id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.CheckMonitorWithResponse(ctx, orgID, id)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		writeTable(e.stdout, []string{"ID", "NAME", "HOST", "PORT", "STATE"}, [][]string{monitorRow(*resp.JSON200)})
	}
	return 0
}

// --- events ---

func cmdEvents(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl events: expected a subcommand (list)")
		return 2
	}
	switch args[0] {
	case "list":
		return eventsList(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl events: unknown subcommand %q\n", args[0])
		return 2
	}
}

func eventsList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("events list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var kinds stringSliceFlag
	fs.Var(&kinds, "kind", "only this event kind; repeat for more than one")
	severity := fs.String("severity", "", "minimum severity")
	since := fs.String("since", "", "only events at or after this RFC 3339 time")
	cursor := fs.String("cursor", "", "page cursor")
	all := fs.Bool("all", false, "follow every page (nextCursor), up to 100 pages")
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}

	var sinceTime *client.EventSince
	if *since != "" {
		t, err := parseTimeFlag(*since)
		if err != nil {
			fmt.Fprintf(e.stderr, "cfctl: --since: %v\n", err)
			return 2
		}
		sinceTime = &t
	}

	var rows [][]string
	err = e.fetchPages(*all, *cursor, func(cur string) (int, []byte, *string, error) {
		params := &client.ListEventsParams{Cursor: strPtr(cur), Since: sinceTime}
		if len(kinds) > 0 {
			k := make(client.EventKindFilter, len(kinds))
			for i, s := range kinds {
				k[i] = client.EventKind(s)
			}
			params.Kind = &k
		}
		if *severity != "" {
			s := client.Severity(*severity)
			params.Severity = &s
		}
		resp, err := e.cwr.ListEventsWithResponse(ctx, orgID, params)
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.JSON200 != nil {
			for _, ev := range resp.JSON200.Items {
				rows = append(rows, []string{ev.Id.String(), string(ev.Kind), string(ev.Severity), ev.At.Format(timeFormat), ev.Summary})
			}
			return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
		}
		return resp.StatusCode(), resp.Body, nil, nil
	})
	if err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		writeTable(e.stdout, []string{"ID", "KIND", "SEVERITY", "AT", "SUMMARY"}, rows)
	}
	return 0
}
