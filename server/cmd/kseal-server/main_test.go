package main

import (
	"testing"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/middleware"
)

func TestComplianceServiceRequiresScopedAuth(t *testing.T) {
	policies := middleware.ProcedurePolicies()
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
	for _, proc := range procs {
		p, ok := policies[proc]
		if !ok || !p.AuthRequired || !p.TenantRequired || len(p.RequiredScopes) == 0 {
			t.Errorf("ComplianceService procedure %q must require auth, tenant binding, and scopes: %+v", proc, p)
		}
	}
}

func TestRegistrySearchAppsRequiresScopedAuth(t *testing.T) {
	p := middleware.ProcedurePolicies()[ksealv1connect.RegistryServiceSearchAppsProcedure]
	if !p.AuthRequired || !p.TenantRequired || len(p.RequiredScopes) == 0 {
		t.Errorf("RegistryService.SearchApps must require auth, tenant binding, and scopes: %+v", p)
	}
}
