package middleware

import (
	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
)

type DeviceCredentialPolicy string

const (
	DeviceCredentialNone        DeviceCredentialPolicy = "none"
	DeviceCredentialPublicNonce DeviceCredentialPolicy = "public_nonce"
	DeviceCredentialAppSecret   DeviceCredentialPolicy = "app_secret"
	DeviceCredentialTrustToken  DeviceCredentialPolicy = "trust_token"
)

type ProcedurePolicy struct {
	AuthRequired          bool
	TenantRequired        bool
	PlatformAdminRequired bool
	RequiredScopes        []string
	DeviceCredential      DeviceCredentialPolicy
}

func (p ProcedurePolicy) public() bool {
	return !p.AuthRequired && !p.TenantRequired && !p.PlatformAdminRequired && len(p.RequiredScopes) == 0 && p.DeviceCredential == DeviceCredentialNone
}

func ProcedurePolicies() map[string]ProcedurePolicy {
	return map[string]ProcedurePolicy{
		ksealv1connect.RegistryServiceCreateTenantProcedure: {AuthRequired: true, PlatformAdminRequired: true, RequiredScopes: []string{"platform:tenant:write"}},
		ksealv1connect.RegistryServiceGetTenantProcedure:    {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},
		ksealv1connect.RegistryServiceListTenantsProcedure:  {AuthRequired: true, PlatformAdminRequired: true, RequiredScopes: []string{"platform:tenant:read"}},
		ksealv1connect.RegistryServiceUpdateTenantProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:write"}},

		ksealv1connect.RegistryServiceCreateAppProcedure:  {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:write"}},
		ksealv1connect.RegistryServiceGetAppProcedure:     {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},
		ksealv1connect.RegistryServiceListAppsProcedure:   {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},
		ksealv1connect.RegistryServiceSearchAppsProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},

		ksealv1connect.RegistryServiceCreateBuildProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:write"}},
		ksealv1connect.RegistryServiceGetBuildProcedure:    {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},
		ksealv1connect.RegistryServiceListBuildsProcedure:  {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"registry:read"}},

		ksealv1connect.RegistryServiceCreatePolicyProcedure:            {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:write"}},
		ksealv1connect.RegistryServiceGetActivePolicyProcedure:         {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:read"}},
		ksealv1connect.RegistryServiceListPoliciesProcedure:            {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:read"}},
		ksealv1connect.RegistryServiceActivatePolicyProcedure:          {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:write"}},
		ksealv1connect.RegistryServiceCreateProtectionProfileProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:write"}},
		ksealv1connect.RegistryServiceListProtectionProfilesProcedure:  {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:read"}},

		ksealv1connect.TrustServiceGetNonceProcedure:             {DeviceCredential: DeviceCredentialPublicNonce},
		ksealv1connect.TrustServiceVerifyAttestationProcedure:    {DeviceCredential: DeviceCredentialPublicNonce},
		ksealv1connect.TrustServiceValidateRequestProofProcedure: {DeviceCredential: DeviceCredentialTrustToken},
		ksealv1connect.ConfigServiceGetConfigProcedure:           {TenantRequired: true, DeviceCredential: DeviceCredentialAppSecret},
		ksealv1connect.ConfigServiceGetPolicyProcedure:           {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"policy:read"}},
		ksealv1connect.IngestServiceSubmitTelemetryProcedure:     {TenantRequired: true, DeviceCredential: DeviceCredentialTrustToken},

		ksealv1connect.WebhookServiceRegisterWebhookProcedure:    {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"webhook:write"}},
		ksealv1connect.WebhookServiceListWebhooksProcedure:       {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"webhook:read"}},
		ksealv1connect.WebhookServiceDeleteWebhookProcedure:      {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"webhook:write"}},
		ksealv1connect.QueryServiceListEventsProcedure:           {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"query:read"}},
		ksealv1connect.QueryServiceGetTenantOverviewProcedure:    {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"query:read"}},
		ksealv1connect.QueryServiceGetTrustSessionStatsProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"query:read"}},
		ksealv1connect.SiemServiceRegisterConnectorProcedure:     {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"siem:write"}},
		ksealv1connect.SiemServiceListConnectorsProcedure:        {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"siem:read"}},
		ksealv1connect.SiemServiceDeleteConnectorProcedure:       {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"siem:write"}},

		ksealv1connect.ComplianceServiceListAuditEventsProcedure:           {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServiceVerifyAuditChainProcedure:          {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServiceGetDataProcessingRegistryProcedure: {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServicePutDataProcessingRecordProcedure:   {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:write"}},
		ksealv1connect.ComplianceServiceIssueKillSwitchProcedure:           {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:write"}},
		ksealv1connect.ComplianceServiceGetKillSwitchStateProcedure:        {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServiceListKillSwitchesProcedure:          {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServiceSetCanaryRolloutProcedure:          {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:write"}},
		ksealv1connect.ComplianceServiceGetCanaryStatusProcedure:           {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:read"}},
		ksealv1connect.ComplianceServicePromoteCanaryProcedure:             {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:write"}},
		ksealv1connect.ComplianceServiceRollbackCanaryProcedure:            {AuthRequired: true, TenantRequired: true, RequiredScopes: []string{"compliance:write"}},
	}
}

func policyFor(procedure string, policies map[string]ProcedurePolicy) (ProcedurePolicy, error) {
	p, ok := policies[procedure]
	if !ok {
		return ProcedurePolicy{}, connect.NewError(connect.CodePermissionDenied, errUnknownProcedure)
	}
	return p, nil
}
