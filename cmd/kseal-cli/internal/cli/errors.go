package cli

import (
	"errors"
	"fmt"
	"io"

	"connectrpc.com/connect"
)

// Exit codes. Distinct, stable codes let CI pipelines branch on the failure
// class (e.g. retry on transient, fail the build on auth/permission).
const (
	ExitOK           = 0
	ExitError        = 1 // generic runtime error
	ExitUsage        = 2 // bad flags / arguments
	ExitAuth         = 3 // authentication / permission denied
	ExitNotFound     = 4 // requested resource does not exist
	ExitUnavailable  = 5 // server unreachable / transient
	ExitInvalidInput = 6 // server rejected the request as invalid
	ExitBlocked      = 7 // a gating check failed (e.g. MASTG release blocked)
)

// usageError marks an error as caused by bad invocation (maps to ExitUsage).
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func newUsageError(format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...)}
}

// authError marks an error as an authentication problem (maps to ExitAuth). It
// covers the locally-detected missing-key case so it shares the exit code the
// server uses when it rejects a key (Unauthenticated), giving CI a single
// "fix your credentials" signal.
type authError struct{ err error }

func (e authError) Error() string { return e.err.Error() }
func (e authError) Unwrap() error { return e.err }

func newAuthError(format string, args ...any) error {
	return authError{err: fmt.Errorf(format, args...)}
}

// blockedError marks a gating failure (maps to ExitBlocked): the command ran
// correctly but a policy/verification gate failed, so CI should stop the
// release without treating it as a generic error.
type blockedError struct{ err error }

func (e blockedError) Error() string { return e.err.Error() }
func (e blockedError) Unwrap() error { return e.err }

func newBlockedError(format string, args ...any) error {
	return blockedError{err: fmt.Errorf(format, args...)}
}

// hintedError carries an actionable remediation hint alongside an underlying
// error. The hint tells the developer *how to fix* the problem ("run X", "set
// $Y") and is rendered on its own line; the wrapped error keeps its original
// class so exit-code mapping (errors.As) is unaffected.
type hintedError struct {
	err  error
	hint string
}

func (e hintedError) Error() string { return e.err.Error() }
func (e hintedError) Unwrap() error { return e.err }
func (e hintedError) hintText() string {
	return e.hint
}

// withHint attaches a remediation hint to err. A nil err stays nil so it is safe
// to wrap conditionally. The hint is intended for a human at a terminal; it is
// never written to stdout or to machine output.
func withHint(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return hintedError{err: err, hint: fmt.Sprintf(format, args...)}
}

// hintOf extracts the remediation hint from anywhere in err's chain, if any.
func hintOf(err error) string {
	var he hintedError
	if errors.As(err, &he) {
		return he.hintText()
	}
	return ""
}

// renderError writes a single, user-facing error report to w. The default form
// is one "error:" line plus an optional "hint:" line — never a Go stack trace.
// With --debug it additionally prints the resolved exit code and the unwrapped
// cause chain so an operator can diagnose layered failures without code access.
func renderError(w io.Writer, err error, debug bool) {
	if err == nil {
		return
	}
	fmt.Fprintln(w, "error:", err.Error())
	if hint := hintOf(err); hint != "" {
		fmt.Fprintln(w, "hint:", hint)
	}
	if !debug {
		return
	}
	fmt.Fprintf(w, "debug: exit code %d\n", ExitCode(err))
	if ce := new(connect.Error); errors.As(err, &ce) {
		fmt.Fprintf(w, "debug: connect code %s\n", ce.Code())
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		fmt.Fprintf(w, "debug: caused by: %v\n", cause)
	}
}

// ExitCode maps an error to a process exit code, translating Connect RPC codes
// into the CLI's stable exit-code contract.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ue usageError
	if errors.As(err, &ue) {
		return ExitUsage
	}
	var ae authError
	if errors.As(err, &ae) {
		return ExitAuth
	}
	var be blockedError
	if errors.As(err, &be) {
		return ExitBlocked
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied:
		return ExitAuth
	case connect.CodeNotFound:
		return ExitNotFound
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeResourceExhausted:
		return ExitUnavailable
	case connect.CodeInvalidArgument, connect.CodeAlreadyExists, connect.CodeFailedPrecondition:
		return ExitInvalidInput
	}
	return ExitError
}
