package main

import (
	"testing"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
)

// TestComplianceServiceRequiresAuth guards against the ComplianceService RPCs
// silently falling through to the device-plane auth path (which trusts the
// request body's tenant_id). Every ComplianceService procedure is a
// control-plane operation and must require a valid API key.
func TestComplianceServiceRequiresAuth(t *testing.T) {
	auth := controlPlaneProcedures()
	procs := []string{
		ksealv1connect.ComplianceServiceListAuditEventsProcedure,
		ksealv1connect.ComplianceServiceVerifyAuditChainProcedure,
		ksealv1connect.ComplianceServiceGetDataProcessingRegistryProcedure,
		ksealv1connect.ComplianceServicePutDataProcessingRecordProcedure,
		ksealv1connect.ComplianceServiceIssueKillSwitchProcedure,
		ksealv1connect.ComplianceServiceGetKillSwitchStateProcedure,
		ksealv1connect.ComplianceServiceListKillSwitchesProcedure,
		ksealv1connect.ComplianceServiceSetCanaryRolloutProcedure,
		ksealv1connect.ComplianceServiceGetCanaryStatusProcedure,
		ksealv1connect.ComplianceServicePromoteCanaryProcedure,
		ksealv1connect.ComplianceServiceRollbackCanaryProcedure,
	}
	for _, p := range procs {
		if !auth[p] {
			t.Errorf("ComplianceService procedure %q must require auth (missing from controlPlaneProcedures)", p)
		}
	}
}

// TestRegistrySearchAppsRequiresAuth ensures the app-search read RPC is treated
// as a control-plane operation requiring an API key, like the rest of
// RegistryService, rather than falling through to the device-plane auth path.
func TestRegistrySearchAppsRequiresAuth(t *testing.T) {
	auth := controlPlaneProcedures()
	if !auth[ksealv1connect.RegistryServiceSearchAppsProcedure] {
		t.Errorf("RegistryService.SearchApps must require auth (missing from controlPlaneProcedures)")
	}
}
