#!/usr/bin/env python3
"""
Azure DevOps Enumerator
Flips an ARM token to an ADO token then enumerates:
  - Identity and org discovery
  - Projects and repos (including git history secret hints)
  - Pipelines (YAML, triggers, service connection usage, addSpnToEnvironment)
  - Service connections (scheme, SP object ID, pipeline access control)
  - Variable groups (plain secrets, KV-backed secrets, open access)
  - Secure files
  - Branch policies (required reviewers, build validation, branch control gaps)
  - Agent pools and self-hosted agents
  - Environments (approval gates, branch control)

Uses current az CLI session. No additional auth required.
"""

import subprocess
import json
import sys
import base64
from collections import defaultdict

# ── Colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(text):
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")

def section(text):
    print(f"\n{BOLD}{YELLOW}  ▸ {text}{RESET}")

def finding(text, level="info"):
    colour = RED if level == "high" else YELLOW if level == "med" else GREEN
    print(f"    {colour}[+]{RESET} {text}")

def warn(text):
    print(f"    {YELLOW}[!]{RESET} {text}")

def info(text):
    print(f"    {CYAN}[-]{RESET} {text}")

# ── Token helpers ─────────────────────────────────────────────────────────────
def get_arm_token():
    """Get current ARM access token from az CLI session."""
    result = subprocess.run(
        ["az", "account", "get-access-token", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout).get("accessToken")
    except json.JSONDecodeError:
        return None

def get_ado_token():
    """Flip ARM session to ADO token using the ADO resource GUID."""
    result = subprocess.run(
        ["az", "account", "get-access-token",
         "--resource", "499b84ac-1321-427f-aa17-267ca6975798",
         "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout).get("accessToken")
    except json.JSONDecodeError:
        return None

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def ado_get(url, token, ignore_errors=False):
    """GET an ADO REST endpoint, return parsed JSON or None."""
    result = subprocess.run(
        ["curl", "-s", "-H", f"Authorization: Bearer {token}",
         "-H", "Content-Type: application/json", url],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        if not ignore_errors:
            warn(f"curl failed: {url}")
        return None
    try:
        data = json.loads(result.stdout)
        # ADO returns {"$id":"1","innerException":...} on auth failure
        if "typeKey" in data and "Exception" in str(data.get("typeKey", "")):
            if not ignore_errors:
                warn(f"ADO error on {url}: {data.get('message', '')[:120]}")
            return None
        return data
    except json.JSONDecodeError:
        if not ignore_errors:
            warn(f"Could not parse JSON from: {url}")
        return None

def az(args, ignore_errors=False):
    """Run an az CLI command, return parsed JSON or None on failure."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            if not ignore_errors:
                warn(f"Command failed: az {' '.join(args)}")
                warn(f"  {result.stderr.strip()[:200]}")
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        warn(f"Timeout: az {' '.join(args)}")
        return None
    except json.JSONDecodeError:
        return None

# ── Identity resolver ─────────────────────────────────────────────────────────
_identity_cache = {}

def resolve_identity(guid, org, token):
    """Resolve an ADO identity GUID to a UPN. Results are cached."""
    if guid in _identity_cache:
        return _identity_cache[guid]
    data = ado_get(
        f"https://vssps.dev.azure.com/{org}/_apis/identities"
        f"?identityIds={guid}&api-version=7.1",
        token, ignore_errors=True
    )
    name = None
    if data and data.get("value"):
        identity = data["value"][0]
        name = (
            identity.get("properties", {}).get("Mail", {}).get("$value")
            or identity.get("providerDisplayName")
            or identity.get("subjectDescriptor")
        )
    _identity_cache[guid] = name or guid
    return _identity_cache[guid]

# ── Identity & org discovery ──────────────────────────────────────────────────
def get_identity_and_orgs(token):
    banner("Identity & Org Discovery")

    # Current ARM identity
    account = az(["account", "show"], ignore_errors=True)
    if account:
        info(f"ARM identity:   {account.get('user', {}).get('name', 'unknown')}")
        info(f"Tenant:         {account.get('tenantId', 'unknown')}")
        info(f"Subscription:   {account.get('name', 'unknown')} ({account.get('id', 'unknown')})")
    else:
        warn("Could not retrieve ARM account - is az login done?")

    # ADO profile (member ID)
    profile = ado_get(
        "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1",
        token
    )
    if not profile:
        warn("Could not retrieve ADO profile - token may not have ADO scope")
        return None, []

    member_id = profile.get("id")
    display_name = profile.get("displayName", "unknown")
    email = profile.get("emailAddress", "unknown")
    info(f"ADO identity:   {display_name} ({email})")
    info(f"ADO member ID:  {member_id}")

    # Org discovery
    accounts = ado_get(
        f"https://app.vssps.visualstudio.com/_apis/accounts?memberId={member_id}&api-version=7.1",
        token
    )
    orgs = []
    if accounts and accounts.get("value"):
        for org in accounts["value"]:
            org_name = org.get("accountName")
            org_id   = org.get("accountId")
            info(f"Org:            {org_name} (id: {org_id})")
            orgs.append(org_name)
    else:
        warn("No orgs discovered from this identity")

    return member_id, orgs

# ── Projects ──────────────────────────────────────────────────────────────────
def enum_projects(org, token):
    banner(f"Projects - {org}")
    data = ado_get(
        f"https://dev.azure.com/{org}/_apis/projects?api-version=7.1",
        token
    )
    projects = []
    if not data or not data.get("value"):
        warn("No projects found or no access")
        return projects
    for p in data["value"]:
        name        = p.get("name", "unknown")
        visibility  = p.get("visibility", "unknown")
        state       = p.get("state", "unknown")
        project_id  = p.get("id")
        info(f"{name} - visibility: {visibility}, state: {state}")
        if visibility == "public":
            finding(f"Public project: {name} - all content readable without auth", "high")
        projects.append({"name": name, "id": project_id})
    return projects

# ── Repos ─────────────────────────────────────────────────────────────────────
def enum_repos(org, project, token):
    section(f"Repos - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=7.1",
        token
    )
    repos = []
    if not data or not data.get("value"):
        info("No repos found")
        return repos
    for r in data["value"]:
        name       = r.get("name", "unknown")
        repo_id    = r.get("id")
        default_br = r.get("defaultBranch", "unknown")
        size       = r.get("size", 0)
        info(f"{name} - default branch: {default_br}, size: {size} bytes")
        repos.append({"name": name, "id": repo_id, "defaultBranch": default_br})

        if size == 0:
            info(f"  (empty repo - skipping file enumeration)")
            continue

        # Try to fetch README for context
        readme = fetch_repo_file(org, project, repo_id, "README.md", token)
        if readme:
            # Surface first 8 non-empty lines as context
            lines = [l.strip() for l in readme.splitlines() if l.strip()][:8]
            for line in lines:
                info(f"  README: {line}")

        # Check for common sensitive file paths
        for fpath in [".env", "terraform.tfvars", "secrets.yaml", "kubeconfig"]:
            content = fetch_repo_file(org, project, repo_id, fpath, token)
            if content:
                finding(f"Sensitive file found in repo {name}: {fpath}", "high")

    repo_map = {r["id"]: r["name"] for r in repos}
    return repos, repo_map

def fetch_repo_file(org, project, repo_id, path, token):
    """Fetch a file from a repo. Returns raw text or None."""
    result = subprocess.run(
        ["curl", "-s",
         "-H", f"Authorization: Bearer {token}",
         f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/items"
         f"?path=/{path}&api-version=7.1&$format=text"],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    # ADO returns JSON error objects for missing files
    try:
        err = json.loads(result.stdout)
        if "typeKey" in err:
            return None
    except json.JSONDecodeError:
        pass
    return result.stdout.strip() or None

# ── Pipelines ─────────────────────────────────────────────────────────────────
def enum_pipelines(org, project, token):
    section(f"Pipelines - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/pipelines?api-version=7.1",
        token
    )
    pipeline_ids = []
    pipeline_map = {}
    if not data or not data.get("value"):
        info("No pipelines found")
        return pipeline_ids, pipeline_map

    for p in data["value"]:
        pid   = p.get("id")
        name  = p.get("name", "unknown")
        folder = p.get("folder", "\\")
        info(f"{name} (id: {pid}, folder: {folder})")
        pipeline_ids.append({"id": pid, "name": name})

        # Fetch full pipeline definition for YAML path and trigger info
        detail = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/{pid}?api-version=7.1",
            token, ignore_errors=True
        )
        if detail:
            yaml_path   = detail.get("configuration", {}).get("path", "unknown")
            repo_name   = detail.get("configuration", {}).get("repository", {}).get("name", "unknown")
            config_type = detail.get("configuration", {}).get("type", "unknown")
            info(f"  YAML: {yaml_path} in {repo_name} (type: {config_type})")

        # Fetch run history for last trigger info
        runs = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/{pid}/runs"
            f"?$top=1&api-version=7.1",
            token, ignore_errors=True
        )
        if runs and runs.get("value"):
            last = runs["value"][0]
            last_result = last.get("result", "unknown")
            last_state  = last.get("state", "unknown")
            info(f"  Last run: result={last_result}, state={last_state}")

    pipeline_map = {p["id"]: p["name"] for p in pipeline_ids}

    # Fetch build definitions for richer YAML analysis (addSpnToEnvironment, sc refs)
    section(f"Pipeline Definitions (YAML analysis) - {project}")
    defs = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/build/definitions?api-version=7.1",
        token, ignore_errors=True
    )
    if defs and defs.get("value"):
        for d in defs["value"]:
            def_id   = d.get("id")
            def_name = d.get("name", "unknown")
            # Fetch full definition for YAML content and variable group refs
            full = ado_get(
                f"https://dev.azure.com/{org}/{project}/_apis/build/definitions/{def_id}?api-version=7.1",
                token, ignore_errors=True
            )
            if not full:
                continue

            # Variable groups linked to this pipeline
            vg_refs = full.get("variableGroups", [])
            for vg in vg_refs:
                info(f"  [{def_name}] variable group: {vg.get('name', '?')} (id: {vg.get('id')})")

            # Service endpoint (service connection) references
            for res in full.get("resources", {}).get("endpoints", []):
                sc_name = res.get("name", "?")
                sc_id   = res.get("id", "?")
                info(f"  [{def_name}] service connection: {sc_name} (id: {sc_id})")

            # Triggers
            triggers = full.get("triggers", [])
            for t in triggers:
                ttype = t.get("triggerType", "unknown")
                info(f"  [{def_name}] trigger: {ttype}")
                if ttype in ("pullRequest", "pullRequestTrigger"):
                    finding(f"[{def_name}] PR trigger - pipeline runs on PR open/update", "med")

            # Fetch and scan the actual YAML file for addSpnToEnvironment
            # The build definitions API process.phases structure only exists for classic
            # pipelines; YAML pipelines need their source file read directly.
            repo_ref = full.get("repository", {})
            yaml_repo_id = repo_ref.get("id")
            yaml_path    = full.get("process", {}).get("yamlFilename") or                            full.get("process", {}).get("yamlFileName") or                            "azure-pipelines.yml"
            if yaml_repo_id:
                yaml_content = fetch_repo_file(org, project, yaml_repo_id, yaml_path, token)
                if yaml_content and "addSpnToEnvironment" in yaml_content:
                    for line in yaml_content.splitlines():
                        if "addSpnToEnvironment" in line and "true" in line.lower():
                            finding(
                                f"[{def_name}] addSpnToEnvironment: true in {yaml_path} "
                                f"- OIDC idToken injected into environment at pipeline runtime",
                                "high"
                            )
                            break

    return pipeline_ids, pipeline_map

# ── Service connections ───────────────────────────────────────────────────────
def enum_service_connections(org, project, token, pipeline_map=None):
    section(f"Service Connections - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?api-version=7.1",
        token
    )
    if not data or not data.get("value"):
        info("No service connections found or no access")
        return []

    scs = []
    for sc in data["value"]:
        name   = sc.get("name", "unknown")
        sctype = sc.get("type", "unknown")
        scheme = sc.get("authorization", {}).get("scheme", "unknown")
        sc_id  = sc.get("id")
        is_shared = sc.get("isShared", False)

        info(f"{name} - type: {sctype}, scheme: {scheme}")

        # SP object ID (present for non-WIF connections)
        sp_id = sc.get("authorization", {}).get("parameters", {}).get("serviceprincipalid")
        if sp_id:
            info(f"  SP object ID / client ID: {sp_id}")

        if scheme == "ServicePrincipal":
            finding(
                f"[{name}] ServicePrincipal scheme - static SP credential stored in ADO; "
                f"no OIDC exchange, credential extraction directly usable",
                "high"
            )
        elif scheme == "WorkloadIdentityFederation":
            info(f"  [{name}] WIF - OIDC token issued at pipeline runtime (no stored secret)")

        if is_shared:
            finding(f"[{name}] Shared service connection - accessible across multiple projects", "med")

        # Pipeline authorisation: check if "grant access to all pipelines" is set
        # This is surfaced via the endpoint's pipelinePermissions
        perms = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/pipelinepermissions"
            f"/endpoint/{sc_id}?api-version=7.1-preview",
            token, ignore_errors=True
        )
        if perms:
            all_pipelines = perms.get("allPipelines", {}).get("authorized", False)
            if all_pipelines:
                finding(
                    f"[{name}] 'Grant access to all pipelines' enabled - "
                    f"any pipeline in project can use this service connection",
                    "high"
                )
            else:
                authorised_ids = [p.get("id") for p in perms.get("pipelines", [])]
                if authorised_ids:
                    names = [
                        (pipeline_map or {}).get(pid, str(pid))
                        for pid in authorised_ids
                    ]
                    info(f"  [{name}] pipelines permitted to use this connection (verify YAML for actual usage): {', '.join(names)}")
                else:
                    info(f"  [{name}] no explicit pipeline authorisation set")

        scs.append({"name": name, "id": sc_id, "type": sctype, "scheme": scheme})

    return scs

# ── Variable groups ───────────────────────────────────────────────────────────
def enum_variable_groups(org, project, token):
    section(f"Variable Groups - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1",
        token
    )
    if not data or not data.get("value"):
        info("No variable groups found")
        return

    for vg in data["value"]:
        name    = vg.get("name", "unknown")
        vg_type = vg.get("type", "Vsts")
        provider = vg.get("providerData", {})
        vault   = provider.get("vault")
        variables = vg.get("variables", {})

        info(f"{name} - type: {vg_type}")

        if vault:
            info(f"  KV-backed - vault: {vault}")
            for var_name, var_val in variables.items():
                raw = var_val.get("value")
                display_val = raw if raw is not None else "null (fetched at runtime)"
                info(f"  Secret: {var_name} -> value: {display_val}")
                finding(
                    f"[{name}] KV-backed secret '{var_name}' in vault '{vault}' - "
                    f"pipeline SP has Key Vault read access; lateral movement path to KV",
                    "high"
                )
        else:
            for var_name, var_val in variables.items():
                is_secret = var_val.get("isSecret", False)
                value     = var_val.get("value", "")
                if is_secret:
                    finding(
                        f"[{name}] Secret variable '{var_name}' stored in ADO - "
                        f"decrypted at pipeline runtime; exfiltrable via pipeline injection",
                        "high"
                    )
                else:
                    info(f"  {var_name} = {value}")

        # Check pipeline access control
        vg_id = vg.get("id")
        perms = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/pipelinepermissions"
            f"/variablegroup/{vg_id}?api-version=7.1-preview",
            token, ignore_errors=True
        )
        if perms:
            all_pipelines = perms.get("allPipelines", {}).get("authorized", False)
            if all_pipelines:
                finding(
                    f"[{name}] Open access - any pipeline in project can use this variable group",
                    "med"
                )

# ── Secure files ──────────────────────────────────────────────────────────────
def enum_secure_files(org, project, token):
    section(f"Secure Files - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/distributedtask/securefiles?api-version=7.1-preview",
        token
    )
    if not data or not data.get("value"):
        info("No secure files found")
        return

    for sf in data["value"]:
        name    = sf.get("name", "unknown")
        sf_id   = sf.get("id")
        created = sf.get("createdBy", {}).get("displayName", "unknown")
        info(f"{name} (id: {sf_id}, created by: {created})")
        finding(
            f"Secure file '{name}' - contents not readable via API; "
            f"retrievable by injecting DownloadSecureFile@1 task into an authorised pipeline",
            "med"
        )

        # Check open access
        perms = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/pipelinepermissions"
            f"/securefile/{sf_id}?api-version=7.1-preview",
            token, ignore_errors=True
        )
        if perms:
            all_pipelines = perms.get("allPipelines", {}).get("authorized", False)
            if all_pipelines:
                finding(
                    f"[{name}] Open access - any pipeline can download this secure file",
                    "high"
                )

# ── Branch policies ───────────────────────────────────────────────────────────
def enum_branch_policies(org, project, token, repo_map=None):
    section(f"Branch Policies - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/policy/configurations?api-version=7.0",
        token
    )
    if not data or not data.get("value"):
        info("No branch policies configured")
        finding("No branch policies on any repo - direct push to default branch may be possible", "high")
        return

    # Group policies by branch/repo for readability
    by_branch = defaultdict(list)
    for policy in data["value"]:
        policy_type  = policy.get("type", {}).get("displayName", "unknown")
        is_enabled   = policy.get("isEnabled", False)
        is_blocking  = policy.get("isBlocking", False)
        settings     = policy.get("settings", {})
        scope        = settings.get("scope", [])

        branch_name = "unknown"
        repo_name   = "unknown"
        for s in scope:
            branch_name = s.get("refName", s.get("matchKind", "unknown"))
            repo_id     = s.get("repositoryId", "")
            repo_name   = (repo_map or {}).get(repo_id, repo_id)

        key = f"{repo_name}:{branch_name}"
        by_branch[key].append({
            "type": policy_type,
            "enabled": is_enabled,
            "blocking": is_blocking,
            "settings": settings
        })

    for branch_key, policies in by_branch.items():
        info(f"Branch: {branch_key}")
        policy_types_present = set()
        for p in policies:
            ptype    = p["type"]
            blocking = "blocking" if p["blocking"] else "non-blocking"
            enabled  = "enabled" if p["enabled"] else "disabled"
            info(f"  {ptype} - {enabled}, {blocking}")
            policy_types_present.add(ptype)

            # Required reviewer check
            if ptype == "Required reviewers":
                reviewers = p["settings"].get("requiredReviewerIds", [])
                for r in reviewers:
                    display = resolve_identity(r, org, token)
                    info(f"    Required reviewer: {display}")
                if not reviewers:
                    finding(f"Required reviewers policy present but no reviewers configured", "med")

            # Build validation check (triggers pipeline on PR)
            if ptype == "Build" and p["enabled"]:
                display_name = p["settings"].get("displayName")
                def_id       = p["settings"].get("buildDefinitionId")
                if display_name:
                    label = f"'{display_name}'"
                elif def_id:
                    label = f"(pipeline id: {def_id})"
                else:
                    label = "(unnamed)"
                finding(
                    f"Build validation policy {label} - "
                    f"pipeline runs during PR (plan phase); "
                    f"malicious YAML in PR branch executes before approval",
                    "high"
                )

            # Branch control / allowed branches
            if ptype == "Branch Control":
                allowed = p["settings"].get("allowedBranches", "")
                info(f"    Allowed branches: {allowed}")
                if not allowed or allowed == "*":
                    finding(
                        f"Branch Control policy allows any branch - "
                        f"service connection usable from feature branches without review",
                        "high"
                    )

        # Missing policy detections
        if "Minimum number of reviewers" not in policy_types_present:
            finding(
                f"No minimum reviewer policy on {branch_key} - "
                f"PR could be self-approved or merged without review",
                "high"
            )
        if "Build" not in policy_types_present:
            info(f"  No build validation on {branch_key}")

# ── Agent pools ───────────────────────────────────────────────────────────────
def enum_agent_pools(org, token):
    section(f"Agent Pools - {org}")
    data = ado_get(
        f"https://dev.azure.com/{org}/_apis/distributedtask/pools?api-version=7.1",
        token
    )
    if not data or not data.get("value"):
        info("No agent pools found")
        return

    for pool in data["value"]:
        pool_id   = pool.get("id")
        pool_name = pool.get("name", "unknown")
        is_hosted = pool.get("isHosted", False)
        pool_type = "Microsoft-hosted" if is_hosted else "self-hosted"
        info(f"{pool_name} (id: {pool_id}) - {pool_type}")

        if not is_hosted:
            finding(
                f"Self-hosted pool '{pool_name}' - agents run on customer infrastructure; "
                f"lateral movement to agent VM possible via pipeline code execution",
                "high"
            )
            # Enumerate agents in pool
            agents = ado_get(
                f"https://dev.azure.com/{org}/_apis/distributedtask/pools/{pool_id}/agents"
                f"?includeCapabilities=true&api-version=7.1",
                token, ignore_errors=True
            )
            if agents and agents.get("value"):
                for agent in agents["value"]:
                    agent_name = agent.get("name", "unknown")
                    agent_os   = agent.get("osDescription", "unknown")
                    agent_ver  = agent.get("version", "unknown")
                    status     = agent.get("status", "unknown")
                    info(f"  Agent: {agent_name} - OS: {agent_os}, version: {agent_ver}, status: {status}")

                    # System capabilities (reveals hostname, user, env vars)
                    caps = agent.get("systemCapabilities", {})
                    for cap_key in ["Agent.ComputerName", "Agent.UserName", "Agent.HomeDirectory"]:
                        val = caps.get(cap_key)
                        if val:
                            info(f"    {cap_key}: {val}")

# ── Environments ──────────────────────────────────────────────────────────────
def enum_environments(org, project, token):
    section(f"Environments - {project}")
    data = ado_get(
        f"https://dev.azure.com/{org}/{project}/_apis/distributedtask/environments?api-version=7.1-preview",
        token
    )
    if not data or not data.get("value"):
        info("No environments found")
        return

    for env in data["value"]:
        env_name = env.get("name", "unknown")
        env_id   = env.get("id")
        info(f"{env_name} (id: {env_id})")

        # Check for approval gates via checks API
        checks = ado_get(
            f"https://dev.azure.com/{org}/{project}/_apis/pipelines/checks/configurations"
            f"?resourceType=environment&resourceId={env_id}&api-version=7.1-preview",
            token, ignore_errors=True
        )
        has_approval = False
        if checks and checks.get("value"):
            for check in checks["value"]:
                check_type = check.get("type", {}).get("name", "unknown")
                info(f"  Check: {check_type}")
                if check_type == "Approval":
                    has_approval = True
                    approvers = check.get("settings", {}).get("approvers", [])
                    for approver in approvers:
                        info(f"    Approver: {approver.get('displayName', '?')}")

        if not has_approval:
            finding(
                f"Environment '{env_name}' has no approval gate - "
                f"deployments to this environment require no human sign-off",
                "high"
            )

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner("Azure DevOps Enumerator")

    # Acquire ADO token
    info("Acquiring ADO token via ARM token flip...")
    ado_token = get_ado_token()
    if not ado_token:
        print(f"{RED}Could not acquire ADO token. Is az login done?{RESET}")
        sys.exit(1)
    info("ADO token acquired")

    # Identity and org discovery
    member_id, orgs = get_identity_and_orgs(ado_token)
    if not orgs:
        warn("No orgs found - cannot continue")
        sys.exit(1)

    for org in orgs:
        banner(f"Organisation: {org}")

        # Agent pools are org-scoped
        enum_agent_pools(org, ado_token)

        # Project-scoped enumeration
        projects = enum_projects(org, ado_token)

        for project in projects:
            project_name = project["name"]
            banner(f"Project: {project_name}")

            repos, repo_map     = enum_repos(org, project_name, ado_token)
            pipeline_ids, pipeline_map = enum_pipelines(org, project_name, ado_token)
            enum_service_connections(org, project_name, ado_token, pipeline_map)
            enum_variable_groups(org, project_name, ado_token)
            enum_secure_files(org, project_name, ado_token)
            enum_branch_policies(org, project_name, ado_token, repo_map)
            enum_environments(org, project_name, ado_token)

    banner("Enumeration Complete")

if __name__ == "__main__":
    main()
