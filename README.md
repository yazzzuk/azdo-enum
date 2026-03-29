# az-ado-enum

Azure DevOps enumeration script for red team and security assessment engagements. Flips an ARM token to an ADO token and walks the full org → project hierarchy.

Uses the current `az` CLI session. No additional authentication required.

## Prerequisites

- `az` CLI installed and authenticated (`az login`)
- `curl` available in PATH
- Python 3.6+
- ADO Contributor on the target project (sufficient for full enumeration). Lower privileges will still enumerate projects, repos, pipelines, agent pools, and branch policies but may return empty results for service connections, secure files, and pipeline permission checks

## Usage

```bash
python3 az_ado_enum.py
```

To target a specific tenant:

```bash
az login --tenant <tenant-id>
python3 az_ado_enum.py
```

## What it enumerates

- Identity and org discovery
- Agent pools (self-hosted vs Microsoft-hosted, agent hostname, OS, user)
- Projects and repos (default branch, sensitive file detection)
- Pipelines (YAML path, triggers, variable group and service connection references, `addSpnToEnvironment`)
- Service connections (type, scheme, SP client ID, permitted pipelines)
- Variable groups (plain variables, ADO-stored secrets, KV-backed secrets)
- Secure files (name, creator, open access)
- Branch policies (minimum reviewers, build validation, required reviewers, missing policy detection)
- Environments (approval gates and approvers)

## Output

- `[+]` red - high severity finding
- `[+]` yellow - medium severity finding
- `[-]` cyan - enumeration info
- `[!]` yellow - command failed or data unavailable

## Example output

```
════════════════════════════════════════════════════════════
  Identity & Org Discovery
════════════════════════════════════════════════════════════
    [-] ARM identity:   j.smith@contoso.com
    [-] Tenant:         xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [-] Subscription:   sub-prod (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    [-] ADO identity:   J Smith (j.smith@contoso.com)
    [-] ADO member ID:  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [-] Org:            contoso (id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

  ▸ Agent Pools - contoso
    [-] Default (id: 1) - self-hosted
    [+] Self-hosted pool 'Default' - agents run on customer infrastructure; lateral movement to agent VM possible via pipeline code execution
    [-]   Agent: vm-prod-azdo - OS: Ubuntu 24.04.1 LTS, version: 4.248.0, status: online
    [-]     Agent.ComputerName: vm-prod-azdo
    [-]     Agent.HomeDirectory: /home/azdoagent/agent

  ▸ Pipeline Definitions (YAML analysis) - platform
    [-]   [policy-pipeline] trigger: continuousIntegration
    [+] [policy-pipeline] addSpnToEnvironment: true in azure-pipelines.yml - OIDC idToken injected into environment at pipeline runtime

  ▸ Service Connections - platform
    [-] sc-platform - type: azurerm, scheme: WorkloadIdentityFederation
    [-]   SP object ID / client ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [-]   [sc-platform] WIF - OIDC token issued at pipeline runtime (no stored secret)
    [-]   [sc-platform] pipelines permitted to use this connection: policy-pipeline, image-build-pipeline
    [-] sc-acr - type: dockerregistry, scheme: ServicePrincipal
    [+] [sc-acr] ServicePrincipal scheme - static SP credential stored in ADO; no OIDC exchange, credential extraction directly usable

  ▸ Variable Groups - platform
    [-] vg-build - type: Vsts
    [-]   acrName = acrprodworkloads
    [-]   imageRepository = invoices-api
    [-] vg-prod-kv - type: AzureKeyVault
    [-]   KV-backed - vault: kv-prod-workloads
    [-]   Secret: prod-signing-key -> value: null (fetched at runtime)
    [+] [vg-prod-kv] KV-backed secret 'prod-signing-key' in vault 'kv-prod-workloads' - pipeline SP has Key Vault read access; lateral movement path to KV

  ▸ Secure Files - platform
    [-] imagesign.pem (id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, created by: A. Lopez)
    [+] Secure file 'imagesign.pem' - contents not readable via API; retrievable by injecting DownloadSecureFile@1 task into an authorised pipeline
    [+] [imagesign.pem] Open access - any pipeline can download this secure file

  ▸ Branch Policies - platform
    [-] Branch: policy-repo:refs/heads/main
    [-]   Minimum number of reviewers - enabled, blocking
    [-]   Build - enabled, blocking
    [+] Build validation policy 'Terraform plan' - pipeline runs during PR (plan phase); malicious YAML in PR branch executes before approval
    [-]   Required reviewers - enabled, blocking
    [-]     Required reviewer: a.lopez@contoso.com
    [-] Branch: app-deploy-repo:refs/heads/main
    [+] No minimum reviewer policy on app-deploy-repo:refs/heads/main - PR could be self-approved or merged without review
    [-]   No build validation on app-deploy-repo:refs/heads/main
```

