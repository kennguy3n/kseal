# kseal private link (regulated tenants)

Private connectivity for regulated tenants (fintech / health / gov) via **AWS
PrivateLink**, so their traffic to kseal never traverses the public internet.
This is the network half of the **Regulated** isolation tier (private link + CMK
+ optional on-prem verifier; see [ARCHITECTURE.md](../ARCHITECTURE.md),
[deployment-onprem.md](./deployment-onprem.md), and the `KSEAL_CMK_KMS_URI` BYOK
env var wired in the chart).

- [What it provisions](#what-it-provisions)
- [No public ingress](#no-public-ingress)
- [Provider setup (kseal side)](#provider-setup-kseal-side)
- [Binding server pods to the NLB](#binding-server-pods-to-the-nlb)
- [Consumer setup (tenant side)](#consumer-setup-tenant-side)
- [Security model](#security-model)
- [Validation](#validation)

---

## What it provisions

Module: [`deploy/terraform/modules/private-link`](../deploy/terraform/modules/private-link).

```
 tenant VPC (account 2222…)                kseal data-plane VPC
 ┌───────────────────────┐                ┌───────────────────────────────┐
 │ interface VPC endpoint │  PrivateLink   │ VPC Endpoint Service           │
 │ vpce-xxxx (ENI, private├───────────────►│  (acceptance_required)          │
 │ IPs in tenant subnets) │   (AWS         │            │                    │
 └───────────────────────┘    backbone)   │   internal NLB :443 (TLS|TCP)   │
                                           │            │ forward            │
                                           │   target group (ip targets)     │
                                           │            │ TargetGroupBinding  │
                                           │   kseal server pods :8080 (h2c)  │
                                           └───────────────────────────────┘
```

| Resource | Purpose |
| --- | --- |
| `aws_lb` (network, **internal**) | Fronts the server; never gets a public IP. |
| `aws_lb_target_group` (ip) | HTTP `/readyz` health check on the traffic port; pods registered dynamically. |
| `aws_lb_listener` | TLS (ACM cert) or raw TCP passthrough to the server's h2c port. |
| `aws_vpc_endpoint_service` | Publishes the NLB as a PrivateLink service; `acceptance_required` on by default. |
| `aws_vpc_endpoint_service_allowed_principal` | Whitelists exactly the tenant principals allowed to connect. |

---

## No public ingress

For regulated tenants there is **no public path**:

- The NLB is `internal = true` (private subnets, no public IP).
- The endpoint service is reachable only by whitelisted principals, and each
  consumer connection still requires manual acceptance.
- Disable the chart's public ingress for these releases (`ingress.enabled:
  false`) and let the default-deny NetworkPolicy keep ingress to in-cluster +
  the NLB target group only.

---

## Provider setup (kseal side)

Reference the module from an environment root and apply:

```hcl
module "private_link" {
  source     = "../../modules/private-link"
  name       = "kseal-prod-regulated"
  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.private_subnet_ids

  tls_certificate_arn = aws_acm_certificate.regulated.arn
  acceptance_required = true
  allowed_principals  = ["arn:aws:iam::222233334444:root"]

  enable_private_dns = true
  private_dns_name   = "private.kseal.example.com"
  tags               = local.tags
}
```

See [`terraform.tfvars.example`](../deploy/terraform/modules/private-link/terraform.tfvars.example)
for the full input set. If `enable_private_dns = true`, publish the TXT record
from the `private_dns_name_verification` output to prove domain ownership before
the name resolves.

---

## Binding server pods to the NLB

Registration is dynamic and NoOps — the
[aws-load-balancer-controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/)
binds Ready server pod IPs to the target group via a `TargetGroupBinding`:

```yaml
apiVersion: elbv2.k8s.aws/v1beta1
kind: TargetGroupBinding
metadata:
  name: kseal-server-privatelink
  namespace: kseal
spec:
  serviceRef:
    name: kseal-server   # the chart's server Service
    port: 8080
  targetGroupARN: <module.private_link.target_group_arn>
  targetType: ip
```

Pods join/leave the target group as they scale or roll, so there is nothing to
register by hand.

---

## Consumer setup (tenant side)

The tenant creates an interface VPC endpoint in their own VPC:

```bash
aws ec2 create-vpc-endpoint \
  --vpc-endpoint-type Interface \
  --vpc-id vpc-tenant \
  --service-name <endpoint_service_name> \
  --subnet-ids subnet-a subnet-b \
  --security-group-ids sg-allow-443 \
  --private-dns-enabled   # only if provider enabled private DNS
```

After you accept the connection request (`acceptance_required = true`), the
tenant reaches kseal at the endpoint's private DNS name (or
`private.kseal.example.com` when private DNS is enabled) — entirely over the AWS
backbone.

---

## Security model

- **No public exposure:** internal NLB + private endpoint service.
- **Explicit allow-list + acceptance:** two independent gates per tenant.
- **TLS in transit:** terminate at the NLB with an ACM cert (`tls_certificate_arn`),
  or keep raw TCP passthrough when the link itself is the trust boundary.
- **Least privilege:** the target group only forwards to Ready pods that pass
  the `/readyz` health check; the chart's default-deny NetworkPolicy bounds
  everything else.
- **Pairs with CMK + on-prem verifier** for the full Regulated tier: data stays
  in the tenant's network path, encrypted under a customer-managed key, with an
  optional customer-hosted verifier.

---

## Validation

```bash
terraform -chdir=deploy/terraform/modules/private-link init -backend=false
terraform -chdir=deploy/terraform/modules/private-link validate
terraform -chdir=deploy/terraform fmt -check -recursive
```
