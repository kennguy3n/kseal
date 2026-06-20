package middleware

import (
	"testing"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func TestAuthInterceptorAllGeneratedProceduresHavePolicy(t *testing.T) {
	policies := ProcedurePolicies()
	procedures := []string{
		ksealv1connect.RegistryServiceCreateTenantProcedure, ksealv1connect.RegistryServiceGetTenantProcedure, ksealv1connect.RegistryServiceListTenantsProcedure, ksealv1connect.RegistryServiceUpdateTenantProcedure,
		ksealv1connect.RegistryServiceCreateAppProcedure, ksealv1connect.RegistryServiceGetAppProcedure, ksealv1connect.RegistryServiceListAppsProcedure, ksealv1connect.RegistryServiceSearchAppsProcedure,
		ksealv1connect.RegistryServiceCreateBuildProcedure, ksealv1connect.RegistryServiceGetBuildProcedure, ksealv1connect.RegistryServiceListBuildsProcedure,
		ksealv1connect.RegistryServiceCreatePolicyProcedure, ksealv1connect.RegistryServiceGetActivePolicyProcedure, ksealv1connect.RegistryServiceListPoliciesProcedure, ksealv1connect.RegistryServiceActivatePolicyProcedure,
		ksealv1connect.RegistryServiceCreateProtectionProfileProcedure, ksealv1connect.RegistryServiceListProtectionProfilesProcedure,
		ksealv1connect.TrustServiceGetNonceProcedure, ksealv1connect.TrustServiceVerifyAttestationProcedure, ksealv1connect.TrustServiceValidateRequestProofProcedure,
		ksealv1connect.ConfigServiceGetConfigProcedure, ksealv1connect.ConfigServiceGetPolicyProcedure, ksealv1connect.IngestServiceSubmitTelemetryProcedure,
		ksealv1connect.WebhookServiceRegisterWebhookProcedure, ksealv1connect.WebhookServiceListWebhooksProcedure, ksealv1connect.WebhookServiceDeleteWebhookProcedure,
		ksealv1connect.QueryServiceListEventsProcedure, ksealv1connect.QueryServiceGetTenantOverviewProcedure, ksealv1connect.QueryServiceGetTrustSessionStatsProcedure,
		ksealv1connect.SiemServiceRegisterConnectorProcedure, ksealv1connect.SiemServiceListConnectorsProcedure, ksealv1connect.SiemServiceDeleteConnectorProcedure,
		ksealv1connect.ComplianceServiceListAuditEventsProcedure, ksealv1connect.ComplianceServiceVerifyAuditChainProcedure, ksealv1connect.ComplianceServiceGetDataProcessingRegistryProcedure,
		ksealv1connect.ComplianceServicePutDataProcessingRecordProcedure, ksealv1connect.ComplianceServiceIssueKillSwitchProcedure, ksealv1connect.ComplianceServiceGetKillSwitchStateProcedure,
		ksealv1connect.ComplianceServiceListKillSwitchesProcedure, ksealv1connect.ComplianceServiceSetCanaryRolloutProcedure, ksealv1connect.ComplianceServiceGetCanaryStatusProcedure,
		ksealv1connect.ComplianceServicePromoteCanaryProcedure, ksealv1connect.ComplianceServiceRollbackCanaryProcedure,
	}
	if len(policies) != len(procedures) {
		t.Fatalf("policy count %d != generated procedure count %d", len(policies), len(procedures))
	}
	for _, procedure := range procedures {
		p, ok := policies[procedure]
		if !ok {
			t.Fatalf("missing policy for %s", procedure)
		}
		if p.public() && p.DeviceCredential != DeviceCredentialPublicNonce {
			t.Fatalf("procedure %s is unintentionally public", procedure)
		}
	}
}

func TestAuthInterceptorRejectsUnknownProcedure(t *testing.T) {
	if _, err := policyFor("/kseal.v1.Unknown/Nope", ProcedurePolicies()); err == nil {
		t.Fatal("unknown procedure must fail closed")
	}
}

func TestPrincipalScopesAreExplicit(t *testing.T) {
	if (&auth.Principal{}).HasScope("registry:read") {
		t.Fatal("empty scope list must not grant access")
	}
	if !(&auth.Principal{Scopes: []string{"registry:*"}}).HasScope("registry:read") {
		t.Fatal("exact scope should grant access")
	}
	if (&auth.Principal{TenantID: "t1", Scopes: []string{"*"}}).HasScope("platform:tenant:write") {
		t.Fatal("tenant wildcard must not grant platform scopes")
	}
	if !(&auth.Principal{PlatformAdmin: true, Scopes: []string{"platform:*"}}).HasScope("platform:tenant:write") {
		t.Fatal("platform wildcard should grant platform scopes to platform admins")
	}
}
