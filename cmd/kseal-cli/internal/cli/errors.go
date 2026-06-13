package cli

import (
	"errors"
	"fmt"

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
