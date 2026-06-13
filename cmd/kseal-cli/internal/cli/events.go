package cli

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newEventsCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query and tail stored risk events",
	}
	cmd.AddCommand(
		newEventsQueryCmd(c),
		newEventsTailCmd(c),
	)
	return cmd
}

// eventFilterFlags is shared by query and tail.
type eventFilterFlags struct {
	appID      string
	eventTypes []string
	riskLevels []string
	start      int64
	end        int64
}

func (f *eventFilterFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.appID, "app-id", "", "filter by app id")
	cmd.Flags().StringSliceVar(&f.eventTypes, "event-type", nil, "filter by event type (repeatable)")
	cmd.Flags().StringSliceVar(&f.riskLevels, "risk-level", nil, "filter by fused risk level (repeatable)")
	cmd.Flags().Int64Var(&f.start, "start", 0, "inclusive lower time bound (unix millis; 0 = unbounded)")
	cmd.Flags().Int64Var(&f.end, "end", 0, "inclusive upper time bound (unix millis; 0 = unbounded)")
}

func (f *eventFilterFlags) request(tenant string, pageSize int32, pageToken string) (*ksealv1.ListEventsRequest, error) {
	types, err := parseEventTypes(f.eventTypes)
	if err != nil {
		return nil, newUsageError("%v", err)
	}
	levels, err := parseTrustLevels(f.riskLevels)
	if err != nil {
		return nil, newUsageError("%v", err)
	}
	return &ksealv1.ListEventsRequest{
		TenantId: tenant, AppId: f.appID, EventTypes: types, RiskLevels: levels,
		StartTime: f.start, EndTime: f.end, PageSize: pageSize, PageToken: pageToken,
	}, nil
}

func newEventsQueryCmd(c *CLI) *cobra.Command {
	var filters eventFilterFlags
	var pageSize int32
	var pageToken string
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query stored risk events with filters and keyset pagination",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			req, err := filters.request(tenant, pageSize, pageToken)
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.query().ListEvents(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			es := resp.Msg.GetEvents()
			views := make([]eventView, 0, len(es))
			for _, e := range es {
				views = append(views, newEventView(e))
			}
			return c.emit(listJSON("events", views, resp.Msg.GetNextPageToken()), eventTable(es))
		},
	}
	filters.bind(cmd)
	cmd.Flags().Int32Var(&pageSize, "page-size", 0, "max results per page")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "pagination token from a previous response")
	return cmd
}

func newEventsTailCmd(c *CLI) *cobra.Command {
	var filters eventFilterFlags
	var interval time.Duration
	var pageSize int32
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Continuously poll for and print new risk events",
		Long: "Poll the event store at a fixed interval and print newly-arrived events as " +
			"they appear. Runs until interrupted (Ctrl-C). Honors the same filters as `query`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if pageSize <= 0 {
				pageSize = 100
			}
			return c.tailEvents(cmd.Context(), tenant, &filters, pageSize, interval)
		},
	}
	filters.bind(cmd)
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "poll interval")
	cmd.Flags().Int32Var(&pageSize, "page-size", 100, "events to fetch per poll")
	return cmd
}

// tailEvents polls newest-first pages and emits only events not seen before, in
// chronological order. It is bounded in memory by pruning the seen-set to the
// most recent IDs.
func (c *CLI) tailEvents(ctx context.Context, tenant string, filters *eventFilterFlags, pageSize int32, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	seen := make(map[string]struct{})
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if c.output != outputJSON {
		// Print the table header once; subsequent events stream as rows.
		_ = (table{Headers: []string{"TIMESTAMP", "ID", "APP_ID", "TYPE", "RISK_LEVEL", "CONFIDENCE"}}).render(c.out)
	}

	poll := func() error {
		req, err := filters.request(tenant, pageSize, "")
		if err != nil {
			return err
		}
		// Per-poll timeout independent of the (long-lived) tail context.
		callCtx := ctx
		var cancel context.CancelFunc
		if c.timeout > 0 {
			callCtx, cancel = context.WithTimeout(ctx, c.timeout)
			defer cancel()
		}
		resp, err := c.query().ListEvents(callCtx, connect.NewRequest(req))
		if err != nil {
			return err
		}
		es := resp.Msg.GetEvents()
		// Emit oldest-first for natural reading order.
		fresh := make([]*ksealv1.EventRecord, 0, len(es))
		for i := len(es) - 1; i >= 0; i-- {
			e := es[i]
			if _, ok := seen[e.GetId()]; ok {
				continue
			}
			seen[e.GetId()] = struct{}{}
			fresh = append(fresh, e)
		}
		for _, e := range fresh {
			if err := c.emitOneEvent(e); err != nil {
				return err
			}
		}
		pruneSeen(seen, es)
		return nil
	}

	// pollOnce classifies a poll's outcome so the long-running tail survives
	// transient blips. It returns stop=true for a normal end (parent context
	// cancelled, e.g. Ctrl-C) and a non-nil err only for a fatal error. A
	// transient server error (Unavailable/DeadlineExceeded/ResourceExhausted,
	// including a per-poll timeout) is logged and retried on the next tick.
	pollOnce := func() (stop bool, err error) {
		if perr := poll(); perr != nil {
			if ctx.Err() != nil {
				return true, nil
			}
			if isTransientError(perr) {
				fmt.Fprintf(c.errOut, "tail: transient error, retrying next interval: %v\n", perr)
				return false, nil
			}
			return false, perr
		}
		return false, nil
	}

	if stop, err := pollOnce(); err != nil || stop {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if stop, err := pollOnce(); err != nil || stop {
				return err
			}
		}
	}
}

// isTransientError reports whether a poll error is worth retrying rather than
// aborting the tail. It mirrors the transient classes in ExitCode.
func isTransientError(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeResourceExhausted:
		return true
	default:
		return false
	}
}

// emitOneEvent renders a single event in the active format (one JSON object per
// line for json, one header-less table row for table) so tail streams cleanly.
func (c *CLI) emitOneEvent(e *ksealv1.EventRecord) error {
	if c.output == outputJSON {
		return renderJSON(c.out, newEventView(e))
	}
	row := table{Rows: eventTable([]*ksealv1.EventRecord{e}).Rows}
	return row.render(c.out)
}

// pruneSeen keeps the seen-set bounded: if it grows large, retain only the IDs
// from the most recent page (which is what subsequent polls can re-observe).
func pruneSeen(seen map[string]struct{}, recent []*ksealv1.EventRecord) {
	const maxSeen = 10000
	if len(seen) <= maxSeen {
		return
	}
	keep := make(map[string]struct{}, len(recent))
	for _, e := range recent {
		keep[e.GetId()] = struct{}{}
	}
	for k := range seen {
		if _, ok := keep[k]; !ok {
			delete(seen, k)
		}
	}
}
