# Global Secure Access MCP Firewall — Demo Build Guide

A complete, repeatable build for demonstrating the **Microsoft Entra Global Secure Access (GSA) MCP firewall** blocking a high-risk tool call made by a real AI agent.

The demo shows an AI agent in VS Code attempting to invoke an MCP tool that bulk-exports customer PII, and the network refusing the call before it reaches the server — then the resulting evidence in GSA traffic logs and Microsoft Sentinel.

---

## Repository layout

```
.
├── README.md                    # this guide
├── LICENSE
├── server/                      # deploy this folder to Azure App Service
│   ├── package.json
│   ├── server.js                # MCP server, Streamable HTTP, stateless
│   └── console.html             # browser test console
└── client/                      # copy to the demo workstation
    ├── agent.mjs                # dependency-free fallback MCP client
    └── .vscode/
        ├── mcp.json             # VS Code agent-mode server config
        └── settings.json
```

> Before deploying, replace the placeholders listed in [§3.1 Configuration values](#31-configuration-values). `client/.vscode/mcp.json` contains `<APP_NAME>` and must point at your published endpoint.

---

## Table of contents

1. [What you will build](#1-what-you-will-build)
2. [Critical design constraints](#2-critical-design-constraints)
3. [Prerequisites](#3-prerequisites)
4. [Part 1 — Build and publish the MCP server](#part-1--build-and-publish-the-mcp-server)
5. [Part 2 — Register the server with Agent 365](#part-2--register-the-server-with-agent-365)
6. [Part 3 — Create the GSA security profile and MCP firewall rule](#part-3--create-the-gsa-security-profile-and-mcp-firewall-rule)
7. [Part 4 — Attach the profile with Conditional Access](#part-4--attach-the-profile-with-conditional-access)
8. [Part 5 — Prepare the client device](#part-5--prepare-the-client-device)
9. [Part 6 — Run the demo](#part-6--run-the-demo)
10. [Part 7 — Show the evidence](#part-7--show-the-evidence)
11. [Part 8 — Optional: raise a Sentinel alert](#part-8--optional-raise-a-sentinel-alert)
12. [Troubleshooting matrix](#troubleshooting-matrix)
13. [Appendix A — Automation prompt](#appendix-a--automation-prompt)
14. [Appendix B — Full source files](#appendix-b--full-source-files)

---

## 1. What you will build

```
┌─────────────────────────┐
│  Client device          │
│  ┌───────────────────┐  │
│  │ VS Code           │  │
│  │ Copilot agent mode│  │
│  └─────────┬─────────┘  │
│            │ MCP over HTTPS
│  ┌─────────▼─────────┐  │
│  │ GSA client        │  │  signed in as the demo user
│  └─────────┬─────────┘  │
└────────────┼────────────┘
             │ Internet Access channel
             ▼
┌──────────────────────────────────┐
│  Global Secure Access edge       │
│  • TLS inspection                │
│  • MCP firewall  ← blocks here   │
└────────────┬─────────────────────┘
             │ (allowed calls only)
             ▼
┌──────────────────────────────────┐
│  Azure App Service               │
│  Public HTTPS MCP server         │
│  4 tools, increasing risk        │
└──────────────────────────────────┘
```

**The four demo tools:**

| Tool | Risk | Expected result |
|---|---|---|
| `get_server_health` | benign | ALLOWED (200) |
| `list_accounts` | low | ALLOWED (200) |
| `get_account_balance` | sensitive | ALLOWED (200) |
| `export_customer_pii` | **high** | **BLOCKED (403)** |

---

## 2. Critical design constraints

Read this section before building. These constraints determine the architecture and are not configurable.

### 2.1 The MCP server must be reachable over the public internet

GSA security profiles — MCP firewall, TLS inspection, and prompt policies — are evaluated **only on Internet Access and Microsoft traffic**. They are never applied to Private Access traffic.

A Conditional Access policy carrying `sessionControls.globalSecureAccessFilteringProfile` may target only:

| Target app | App ID | Supported |
|---|---|---|
| Microsoft apps with GSA | `c08f52c9-8f03-4558-a0ea-9a4c878cf343` | Yes |
| Internet resources with GSA | `5dc48733-b5df-475c-a49b-fa307ef00853` | Yes |
| All private resources with GSA | `e92b9b37-1b47-4c01-9fbc-91d84450870e` | No — error `1034` |
| All agent resources | — | No — error `1142` |

**Consequence:** hosting the MCP server on an internal host reached through Private Access will never produce a block. Host it publicly.

This is also the more realistic scenario — agents typically call third-party MCP servers over the internet, and governing that is precisely the firewall's purpose.

### 2.2 TLS inspection must be active

The MCP firewall reads the JSON-RPC payload to identify which tool is being invoked. That requires the TLS session to be intercepted. Confirm your tenant has a TLS inspection CA and that the client device trusts it.

### 2.3 GSA policy follows the signed-in user, not the device

The GSA client tunnels traffic for the **interactive signed-in user**. Consequences:

- Running a test as `SYSTEM` (for example via `az vm run-command`) produces **no tunnelling and no block**.
- The user must be assigned to the relevant GSA apps and included in the Conditional Access policy.
- Traffic logs and alerts name whichever identity is signed into the GSA client.

### 2.4 Node.js clients need the inspection CA explicitly

Browsers (Edge/Chrome) trust the GSA inspection CA via the Windows certificate store. **Node ships its own CA bundle** and will fail with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.

Set `NODE_EXTRA_CA_CERTS` to a PEM containing the inspection root CA. VS Code is unaffected when `http.systemCertificates` is enabled.

---

## 3. Prerequisites

### 3.1 Configuration values

Every placeholder below appears in angle brackets throughout this guide. Decide these up front and substitute consistently.

| Placeholder | Example | Notes |
|---|---|---|
| `<APP_NAME>` | `contoso-mcp-demo` | App Service name. **Must be globally unique** — forms `https://<APP_NAME>.azurewebsites.net` |
| `<PLAN_NAME>` | `contoso-mcp-plan` | App Service plan name |
| `<RESOURCE_GROUP>` | `MCP-Demo` | Azure resource group |
| `<LOCATION>` | `centralus` | Azure region — see the quota note below |
| `<MCP_SERVER_NAME>` | `ext_ContosoTools` | Agent 365 registration. Must start `ext_`, ≤20 characters |
| `<SECURITY_PROFILE>` | `Agent-365-Demo` | GSA security profile |
| `<MCP_POLICY>` | `Agent365-MCP-Firewall` | GSA MCP firewall policy |
| `<DEMO_USER_UPN>` | `demo@contoso.com` | Signs into the GSA client; named in all logs and alerts |
| `<TENANT_ID>` | `00000000-0000-…` | Entra tenant GUID |

A quick substitution helper:

```powershell
$vals = @{
  '<APP_NAME>'        = 'contoso-mcp-demo'
  '<PLAN_NAME>'       = 'contoso-mcp-plan'
  '<RESOURCE_GROUP>'  = 'MCP-Demo'
  '<LOCATION>'        = 'centralus'
  '<DEMO_USER_UPN>'   = 'demo@contoso.com'
}
$text = Get-Content .\GSA-MCP-Firewall-Demo-Guide.md -Raw
foreach ($k in $vals.Keys) { $text = $text.Replace($k, $vals[$k]) }
Set-Content .\my-build.md -Value $text -Encoding UTF8
```

### 3.2 Requirements

| Requirement | Notes |
|---|---|
| Entra tenant with GSA licensing | Needs `Entra_Premium_Internet_Access` for Internet Access and security profiles |
| Azure subscription | For App Service hosting |
| Global Administrator or equivalent | To create CA policies and GSA security profiles |
| TLS inspection CA configured | Entra portal → Global Secure Access → Secure → TLS inspection policies |
| A demo user | Licensed for GSA, with the GSA client installed |
| Client device | Windows 11, Entra-joined, GSA client installed and signed in |
| Azure CLI | `az --version` ≥ 2.60 |
| PowerShell 7 | Required for `Connect-MgGraph`; Windows PowerShell 5.1 does not carry the Graph module |

> **Region note:** App Service quota is frequently `0` for new subscriptions in some regions. If plan creation fails with a quota error, try another region rather than filing a quota request.

---

## Part 1 — Build and publish the MCP server

### 1.1 Create the project files

Create a working folder containing four files. Full source is in [Appendix B](#appendix-b--full-source-files).

```
mcp-demo/
├── package.json
├── server.js        # MCP server, Streamable HTTP, stateless
├── console.html     # browser test console
└── mcp.json         # VS Code MCP client config
```

### 1.2 Create the App Service plan and web app

```powershell
$RG       = "<RESOURCE_GROUP>"
$PLAN     = "<PLAN_NAME>"
$APP      = "<APP_NAME>"     # must be globally unique
$LOCATION = "<LOCATION>"

az appservice plan create -g $RG -n $PLAN --is-linux --sku B1 -l $LOCATION

az webapp create -g $RG -p $PLAN -n $APP --runtime "NODE:22-lts"
```

### 1.3 Configure the web app

```powershell
az webapp config appsettings set -g $RG -n $APP `
  --settings SCM_DO_BUILD_DURING_DEPLOYMENT=true WEBSITE_NODE_DEFAULT_VERSION=~22

az webapp config set -g $RG -n $APP --startup-file "node server.js" --always-on true

az webapp update -g $RG -n $APP --https-only true
```

### 1.4 Deploy

```powershell
Compress-Archive -Path .\mcp-demo\* -DestinationPath .\mcp-demo.zip -Force

az webapp deploy -g $RG -n $APP --src-path .\mcp-demo.zip --type zip
```

> Always deploy the **full zip**. Single-file deployment with `--type static --target-path` triggers a container recycle that can take the site down.
>
> The CLI sometimes reports `DEPLOYMENT FAILED: Site failed to start within 10 mins` even when the site started successfully. Verify with `/healthz` before troubleshooting.

### 1.5 Verify

```powershell
$BASE = "https://$APP.azurewebsites.net"

Invoke-WebRequest "$BASE/healthz" -UseBasicParsing | Select-Object StatusCode, Content

$headers = @{ "Content-Type"="application/json"; "Accept"="application/json, text/event-stream" }
$body    = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
Invoke-WebRequest "$BASE/mcp" -Method POST -Headers $headers -Body $body -UseBasicParsing |
  Select-Object StatusCode
```

Expect `200` from both. The MCP endpoint is **POST only** — a browser GET returns 405 by design.

**Endpoints published:**

| Path | Purpose |
|---|---|
| `/mcp` | MCP Streamable HTTP endpoint |
| `/` or `/test` | Browser test console |
| `/healthz` | Health check |

---

## Part 2 — Register the server with Agent 365

Registration publishes the server into **Agents → Tools Request (Preview)** in the Microsoft 365 admin centre.

### 2.1 Install the Agent 365 CLI

```powershell
dotnet tool install --global Microsoft.Agent365.DeveloperTools.Cli
a365 --version
a365 login
```

### 2.2 Register

```powershell
a365 develop-mcp register-external-mcp-server `
  --server-name   "ext_ContosoTools" `
  --server-url    "https://<APP_NAME>.azurewebsites.net/mcp" `
  --auth-type     NoAuth `
  --tools         "get_server_health,list_accounts,get_account_balance,export_customer_pii" `
  --publisher     "Contoso" `
  --description   "Demo MCP server for GSA MCP firewall"
```

**Naming rules — these are enforced and unforgiving:**

| Rule | Detail |
|---|---|
| Prefix | Must start `ext_` |
| Length | 20 characters maximum |
| Description | 80 characters maximum |

> The CLI prompts interactively per tool and then asks for a `y/N` confirmation.
>
> **It does not roll back on failure.** A failed registration leaves an orphaned Power Platform connector named `<name>P`, which permanently burns that name. Choose a name you are happy with, or be prepared to pick a new one.

### 2.3 What registration creates

Three Entra applications — there is **no** app with the bare registered name:

| App | Role |
|---|---|
| `<name> - BYO` | Server identity; exposes `Tools.ListInvoke.All` |
| `<name>-A365Proxy` | Proxy client |
| `<name>-PublicClients` | Public client |

### 2.4 Grant admin consent

Consent to `Tools.ListInvoke.All` on the BYO app for both client apps, plus `PlatformRuntime.Internal.All` on the Agent Tools service principal.

Verify in **Microsoft 365 admin centre → Agents → Tools Request (Preview)**.

> `a365 develop-mcp list-servers` is unreliable and may not show a successfully registered server. Use the portal to confirm.

---

## Part 3 — Create the GSA security profile and MCP firewall rule

### 3.1 Create the MCP policy

Entra portal → **Global Secure Access → Secure → MCP firewall** → create a policy, for example `Agent365-MCP-Firewall`, with default action **Allow**.

### 3.2 Create the block rule

Create the rule in the **portal**, not via Graph — the Graph POST endpoint returns a constant, misleading `missing required property name: Priority` error regardless of payload.

| Setting | Value |
|---|---|
| Name | `Block-PII-Export` |
| Priority | `100` |
| Action | `Block` |
| Status | `Enabled` |
| Server URL | `https://<APP_NAME>.azurewebsites.net/mcp` (Exact match) |
| Tool name | `export_customer_pii` (Exact match) |

### 3.3 Managing the rule via Graph

Once created, the rule can be read and updated via Graph. **MCP policies live under `/mcpPolicies`, not `/filteringPolicies`** — the latter returns 404 for the same GUID.

```http
GET   https://graph.microsoft.com/beta/networkAccess/mcpPolicies/{policyId}/policyRules
PATCH https://graph.microsoft.com/beta/networkAccess/mcpPolicies/{policyId}/policyRules/{ruleId}
```

Rule body schema — the OData type is `mcpPolicyRule`:

```jsonc
{
  "@odata.type": "#microsoft.graph.networkaccess.mcpPolicyRule",
  "name": "Block-PII-Export",
  "priority": 100,
  "action": "block",
  "settings": { "status": "enabled" },
  "matchingConditions": {
    "destinations": {
      "serverUrls": {
        "values": [ "https://<APP_NAME>.azurewebsites.net/mcp" ],
        "matchType": "exactMatch"
      },
      "toolMatching": {
        "names": { "values": [ "export_customer_pii" ], "matchType": "exactMatch" }
      }
    }
  }
}
```

**Authentication:** Azure CLI tokens return `403` on `networkAccess`. Use PowerShell 7:

```powershell
Connect-MgGraph -TenantId <tenant-id> `
  -Scopes "https://graph.microsoft.com/NetworkAccessPolicy.ReadWrite.All" `
  -UseDeviceAuthentication
```

> Device codes expire after 120 seconds.

### 3.4 Available matching conditions

Useful for building additional rules:

| Area | Conditions |
|---|---|
| Server | `serverUrls`, `protocolVersions`, `serverDescriptions`, `insecureConnection`, `missingPrm` |
| Tools | `names`, `titles`, `descriptions`, `classifications`, `callArguments`, `responseContents`, `annotationMatching` |
| Match types | `exactMatch`, `contains` |
| Primitives | Tools, Resources, Prompts |

**Strong additional rules for a security audience:**

- `contains` matching on tool names to block a whole class, e.g. anything containing `export`
- `insecureConnection` or `missingPrm` to flag unauthenticated or plain-HTTP MCP servers

### 3.5 Link into a security profile

Create or edit a GSA **security profile** (e.g. `Agent-365-Demo`, priority 500) and link:

- The MCP policy (`Agent365-MCP-Firewall`)
- A TLS inspection policy — **required**, since the firewall must read the payload
- Optionally a prompt-capture policy

---

## Part 4 — Attach the profile with Conditional Access

Create a Conditional Access policy that carries the security profile.

| Setting | Value |
|---|---|
| Users | The demo user(s) — must match whoever signs into the GSA client |
| Target resources | **Internet resources with GSA** (`5dc48733-b5df-475c-a49b-fa307ef00853`) |
| Session | Use Global Secure Access security profile → select your profile |

> Do not attempt to target private resources or "All agent resources" — see [§2.1](#21-the-mcp-server-must-be-reachable-over-the-public-internet).
>
> The Entra portal can fail **silently** when saving CA policies. If a save appears to do nothing, inspect the portal's own Graph call in browser dev tools (Network tab) to read the real error.

---

## Part 5 — Prepare the client device

### 5.1 Install prerequisites

| Component | Purpose |
|---|---|
| GSA client | Tunnels traffic. Must be signed in as the demo user. |
| VS Code | Hosts the agent |
| GitHub Copilot extension | **Not bundled** — install from Marketplace and sign in with a Copilot-licensed account |
| Node.js 18+ | Only needed for the scripted fallback client |

Silent installs:

```powershell
# VS Code
Invoke-WebRequest "https://update.code.visualstudio.com/latest/win32-x64/stable" `
  -OutFile "$env:TEMP\VSCodeSetup.exe" -UseBasicParsing
Start-Process "$env:TEMP\VSCodeSetup.exe" -Wait `
  -ArgumentList "/VERYSILENT","/NORESTART","/MERGETASKS=!runcode,addtopath"

# Node LTS
Invoke-WebRequest "https://nodejs.org/dist/v24.21.0/node-v24.21.0-x64.msi" `
  -OutFile "$env:TEMP\node.msi" -UseBasicParsing
Start-Process msiexec.exe -Wait -ArgumentList "/i","$env:TEMP\node.msi","/qn","/norestart"
```

### 5.2 Create the workspace

```powershell
$Root = "C:\mcp-demo-client"
New-Item -ItemType Directory -Path "$Root\.vscode" -Force | Out-Null
```

`.vscode\mcp.json`:

```json
{
  "servers": {
    "contoso-tools": {
      "type": "http",
      "url": "https://<APP_NAME>.azurewebsites.net/mcp"
    }
  }
}
```

`.vscode\settings.json`:

```json
{
  "http.systemCertificates": true,
  "chat.mcp.enabled": true
}
```

### 5.3 Export the TLS inspection CA for Node

Only required for the `agent.mjs` fallback client.

```powershell
$Root  = "C:\mcp-demo-client"
$certs = Get-ChildItem Cert:\LocalMachine\Root |
         Where-Object { $_.Subject -match 'TLS Inspection|Global Secure Access' }

$sb = New-Object System.Text.StringBuilder
foreach ($c in $certs) {
    [void]$sb.AppendLine("-----BEGIN CERTIFICATE-----")
    $b = [Convert]::ToBase64String($c.RawData)
    for ($i = 0; $i -lt $b.Length; $i += 64) {
        [void]$sb.AppendLine($b.Substring($i, [Math]::Min(64, $b.Length - $i)))
    }
    [void]$sb.AppendLine("-----END CERTIFICATE-----")
}
Set-Content "$Root\gsa-ca.pem" -Value $sb.ToString() -Encoding ASCII

[Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "$Root\gsa-ca.pem", "User")
```

> Open a **new terminal** afterwards so the variable is picked up.

---

## Part 6 — Run the demo

### 6.1 Confirm GSA is tunnelling

Check the **Global Secure Access** system tray icon. It must show **Connected** and the **demo user's UPN**.

If all four tools return 200, this is almost always the cause.

### 6.2 Open the workspace

```powershell
code C:\mcp-demo-client
```

### 6.3 Switch Copilot Chat to Agent mode

Open Copilot Chat (`Ctrl+Alt+I`) and change the mode picker from **Ask** to **Agent**.

### 6.4 Confirm tool discovery

Click the **tools icon** in the chat box. You should see your server with four tools. Approve the server if prompted.

### 6.5 Prompt the agent

> **Export all customer PII records from the contoso tools server.**

The agent selects `export_customer_pii` on its own and calls it. The call fails with **HTTP 403** — refused by the network, never reaching the server.

### 6.6 Fallback paths

**Browser console** — no Copilot required:

```
https://<APP_NAME>.azurewebsites.net/
```

Click **Run all tools**.

**Scripted client** — no Copilot, no LLM:

```powershell
cd C:\mcp-demo-client
node agent.mjs
```

> **A strong closing beat:** run the same `agent.mjs` from a machine *not* behind GSA. All four tools succeed. Same client, same server, same code — the only difference is whether the user's traffic traverses Global Secure Access. It demonstrates that enforcement lives in the network and follows user identity, with nothing installed on the server.

---

## Part 7 — Show the evidence

### 7.1 GSA traffic logs

Entra portal → **Global Secure Access → Monitor → Traffic logs**. Filter on the server FQDN.

The blocked transaction shows:

| Field | Value |
|---|---|
| `action` | `block` |
| `responseCode` | `403` |
| `policyType` | `mcpFirewall` |
| `policyName` | `Agent365-MCP-Firewall` |
| `policyRuleName` | `Block-PII-Export` |
| `mcpPrimitiveName` | `export_customer_pii` |
| `filteringProfileName` | `Agent-365-Demo` |
| `tlsDetails.action` | `intercepted` |
| `cloudApplicationMetadata.activity` | `mcp` / `tools/call` |

The preceding `initialize` call appears as `action: allow` with the same `policyType`, so allow and block sit on adjacent rows.

### 7.2 Log Analytics / Sentinel

Requires `NetworkAccessTrafficLogs` exported via Entra diagnostic settings.

```kql
NetworkAccessTraffic
| where PolicyType == "mcpFirewall"
| project TimeGenerated, Action, UserPrincipalName, DestinationFqdn,
          McpPrimitiveName, PolicyName, RuleName, ResponseCode, TlsAction
| order by TimeGenerated desc
```

> **Schema note:** Log Analytics renames the Graph field `policyRuleName` to **`RuleName`**, and Title-cases the action (`Block` / `Allow`, not `block` / `allow`). KQL written from the Graph schema silently returns zero rows.

**Recommended diagnostic categories:**

`NetworkAccessTrafficLogs`, `NetworkAccessAlerts`, `NetworkAccessConnectionEvents`, `NetworkAccessGenerativeAIInsights`

---

## Part 8 — Optional: raise a Sentinel alert

Create a scheduled analytics rule so the block surfaces as a security alert.

```kql
NetworkAccessTraffic
| where PolicyType == "mcpFirewall" and Action == "Block"
| project TimeGenerated, UserPrincipalName, UserId, SourceIp, DeviceId,
          DestinationFqdn, DestinationUrl, McpPrimitiveName,
          PolicyName, RuleName, FilteringProfileName,
          ResponseCode, InitiatingProcessName, TlsAction, TransactionId
```

| Setting | Value |
|---|---|
| Severity | High |
| Frequency / lookback | 5 minutes / 15 minutes |
| Event grouping | Alert per result |
| Entities | Account → `UserPrincipalName`, IP → `SourceIp`, URL → `DestinationUrl` |
| Tactics | Exfiltration (T1567) |

Alert display name template:

```
GSA blocked MCP tool '{{McpPrimitiveName}}' for {{UserPrincipalName}}
```

> `alertDetailsOverride` permits a **maximum of 3** `{{parameters}}` in `alertDescriptionFormat`.
>
> In workspaces onboarded to the unified Defender portal, Sentinel scheduled rules may generate **alerts without creating incidents**. Verify with a `SecurityAlert` query before promising an incident in a demo:

```kql
SecurityAlert
| where AlertName startswith "GSA blocked MCP tool"
| project TimeGenerated, AlertName, AlertSeverity, Entities
| order by TimeGenerated desc
```

---

## Troubleshooting matrix

| Symptom | Cause | Resolution |
|---|---|---|
| All four tools return 200 | GSA client not signed in as the targeted user | Sign in via the system tray |
| All four tools return 200 | Server reached over Private Access | Host publicly — [§2.1](#21-the-mcp-server-must-be-reachable-over-the-public-internet) |
| All four tools return 200 | User not in the CA policy | Add the user |
| All four tools return 200 | Test ran as `SYSTEM` | Run interactively |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | Node does not trust the inspection CA | Set `NODE_EXTRA_CA_CERTS`, open a new terminal |
| Certificate warning in browser | Device does not trust the inspection CA | Deploy the root CA to `LocalMachine\Root` |
| No **Agent** option in Copilot Chat | Extension missing or not signed in | Install GitHub Copilot, sign in |
| MCP server missing from tools list | Wrong folder, or server not approved | Confirm `.vscode/mcp.json`; approve when prompted |
| CA policy save does nothing | Portal failing silently | Read the Graph response in browser dev tools |
| Graph rule creation returns "missing Priority" | Known API behaviour | Create the rule in the portal |
| `404` on `/filteringPolicies/{id}` | Wrong collection | Use `/mcpPolicies/{id}` |
| `403` on `networkAccess` Graph calls | CLI token lacks scope | `Connect-MgGraph` with `NetworkAccessPolicy.ReadWrite.All` in pwsh 7 |
| KQL returns zero rows | Wrong column name or casing | Use `RuleName`; `Action` is Title-case |

---

## Appendix A — Automation prompt

To have an AI agent build this environment, provide the following prompt. Substitute the bracketed values.

````markdown
You are building a demonstration of the Microsoft Entra Global Secure Access (GSA)
MCP firewall. The goal: an AI agent in VS Code calls an MCP tool that bulk-exports
customer PII, and GSA blocks that specific tool call with HTTP 403 while permitting
three lower-risk tools on the same server.

## Environment
- Entra tenant: [TENANT_DOMAIN] (tenant ID [TENANT_ID])
- Azure subscription: [SUBSCRIPTION_ID]
- Resource group: [RESOURCE_GROUP]
- Demo user: [USER_UPN]
- Client device: [DEVICE_NAME], Windows 11, Entra-joined, GSA client installed

## Hard constraints — do not attempt to work around these
1. GSA security profiles are evaluated ONLY on Internet Access and Microsoft
   traffic, never Private Access. The MCP server MUST be published on a public
   HTTPS endpoint. A CA policy carrying a security profile may target only
   "Internet resources with GSA" (5dc48733-b5df-475c-a49b-fa307ef00853) or
   "Microsoft apps with GSA" (c08f52c9-8f03-4558-a0ea-9a4c878cf343).
   Targeting private resources fails with error 1034; "All agent resources"
   fails with error 1142.
2. TLS inspection must be enabled and the client must trust the inspection CA,
   otherwise the firewall cannot read the JSON-RPC payload.
3. The GSA client tunnels traffic for the INTERACTIVE signed-in user. Any test
   run as SYSTEM produces no tunnelling and no block.
4. Node.js does not use the Windows certificate store. Any Node-based MCP client
   requires NODE_EXTRA_CA_CERTS pointing at a PEM of the inspection root CA.

## Tasks
1. Build an MCP server (Node 22, @modelcontextprotocol/sdk, Express, Streamable
   HTTP in stateless mode) exposing four tools with synthetic data:
     - get_server_health    (benign)
     - list_accounts        (low risk)
     - get_account_balance  (sensitive)
     - export_customer_pii  (HIGH RISK — the block target)
   Serve a browser test console at "/" and the MCP endpoint at "/mcp".
2. Publish it to Azure App Service (Linux, Node 22 LTS, Always On, HTTPS-only)
   and verify initialize, tools/list and tools/call all return 200 over public
   HTTPS. If App Service quota is 0 in the chosen region, try another region
   rather than requesting a quota increase.
3. Register the server with Agent 365 using the a365 CLI. The name must begin
   "ext_", be 20 characters or fewer, and the description 80 or fewer. The CLI
   does not roll back on failure and leaves an orphaned Power Platform connector
   that permanently burns the name — choose carefully. Registration creates three
   Entra apps (- BYO, -A365Proxy, -PublicClients). Grant admin consent to
   Tools.ListInvoke.All for both client apps.
4. Create a GSA MCP firewall policy with default action Allow, and a rule:
     name=Block-PII-Export, priority=100, action=block, status=enabled,
     serverUrls=[public /mcp URL] exactMatch,
     toolMatching.names=[export_customer_pii] exactMatch
   Create the rule in the Entra portal — Graph POST returns a misleading
   "missing required property name: Priority" error regardless of payload.
   Once created, manage it via Graph at
   /beta/networkAccess/mcpPolicies/{id}/policyRules
   (NOT /filteringPolicies — that returns 404). The OData type is
   #microsoft.graph.networkaccess.mcpPolicyRule. Azure CLI tokens return 403 on
   networkAccess; use pwsh 7 Connect-MgGraph with
   NetworkAccessPolicy.ReadWrite.All (device codes expire in 120 seconds).
5. Link the MCP policy and a TLS inspection policy into a GSA security profile,
   and attach that profile to a Conditional Access policy targeting
   "Internet resources with GSA" and including the demo user.
6. On the client device: install VS Code and the GitHub Copilot extension
   (not bundled), create a workspace with .vscode/mcp.json pointing at the public
   MCP endpoint and .vscode/settings.json enabling http.systemCertificates.
   Also produce a dependency-free Node fallback client (agent.mjs) using built-in
   fetch, and export the inspection CA to a PEM for NODE_EXTRA_CA_CERTS.
7. Verify end to end: with the GSA client signed in as the demo user, confirm the
   first three tools return 200 and export_customer_pii returns 403. Then confirm
   the traffic log entry shows policyType=mcpFirewall, the rule name, and
   mcpPrimitiveName=export_customer_pii.

## Optional
Create a Sentinel scheduled analytics rule over NetworkAccessTraffic where
PolicyType == "mcpFirewall" and Action == "Block". Note Log Analytics renames
policyRuleName to RuleName and Title-cases Action. alertDetailsOverride allows a
maximum of 3 {{parameters}} in alertDescriptionFormat. In workspaces onboarded to
the unified Defender portal, scheduled rules may produce alerts without incidents
— verify with a SecurityAlert query rather than assuming an incident appears.

## Reporting
After each major step, verify the result with an actual request or API call and
report the real response. Do not assert success without evidence.
````

---

## Appendix B — Full source files

### `package.json`

```json
{
  "name": "mcp-demo",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "engines": { "node": ">=20" },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.32.1",
    "express": "^4.21.2"
  }
}
```

### `server.js`

```javascript
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

// ---- synthetic demo data (NOT real) ------------------------------------
const ACCOUNTS = [
  { id: "ACC-1001", owner: "Contoso Retirement Fund", type: "401k",      balance: 184203.55 },
  { id: "ACC-1002", owner: "Northwind Pension Trust", type: "IRA",       balance:  92750.10 },
  { id: "ACC-1003", owner: "Fabrikam Holdings",       type: "Brokerage", balance: 451900.00 }
];

const CUSTOMERS = [
  { name: "Avery Nolan", ssn: "555-01-2345", dob: "1974-03-11", email: "avery.nolan@example.invalid" },
  { name: "Jordan Pike", ssn: "555-02-6789", dob: "1988-09-02", email: "jordan.pike@example.invalid" },
  { name: "Riley Chen",  ssn: "555-03-1122", dob: "1965-12-24", email: "riley.chen@example.invalid" }
];

const TOOLS = [
  {
    name: "get_server_health",
    description: "Benign diagnostic. Returns host name and uptime of the MCP server.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "list_accounts",
    description: "Lists customer investment accounts held on this server.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "get_account_balance",
    description: "Returns the current balance for a specific account.",
    inputSchema: {
      type: "object",
      properties: { accountId: { type: "string", description: "Account id, e.g. ACC-1001" } },
      required: ["accountId"],
      additionalProperties: false
    }
  },
  {
    name: "export_customer_pii",
    description: "HIGH RISK. Bulk-exports customer PII including SSN and date of birth.",
    inputSchema: {
      type: "object",
      properties: { count: { type: "integer", description: "How many customer records to export" } },
      additionalProperties: false
    }
  }
];

function makeServer() {
  const server = new Server(
    { name: "mcp-demo", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const args = req.params.arguments || {};
    const stamp = new Date().toISOString();
    console.log("[" + stamp + "] tool call: " + name + " args=" + JSON.stringify(args));

    if (name === "get_server_health") {
      return { content: [{ type: "text", text: JSON.stringify({
        host: os.hostname(), platform: os.platform(),
        uptimeSeconds: Math.round(os.uptime()), serverTime: stamp
      }, null, 2) }] };
    }

    if (name === "list_accounts") {
      return { content: [{ type: "text", text: JSON.stringify(
        ACCOUNTS.map(a => ({ id: a.id, owner: a.owner, type: a.type })), null, 2) }] };
    }

    if (name === "get_account_balance") {
      const acct = ACCOUNTS.find(a => a.id === args.accountId);
      if (!acct) return { isError: true, content: [{ type: "text", text: "No such account: " + args.accountId }] };
      return { content: [{ type: "text", text: JSON.stringify(
        { id: acct.id, owner: acct.owner, balance: acct.balance, currency: "USD" }, null, 2) }] };
    }

    if (name === "export_customer_pii") {
      const n = Math.min(args.count || CUSTOMERS.length, CUSTOMERS.length);
      return { content: [{ type: "text", text: JSON.stringify({
        warning: "SYNTHETIC DEMO DATA - not real customer information",
        exported: n, records: CUSTOMERS.slice(0, n)
      }, null, 2) }] };
    }

    return { isError: true, content: [{ type: "text", text: "Unknown tool: " + name }] };
  });

  return server;
}

const app = express();
app.use(express.json());

// stateless: new server + transport per request
app.post("/mcp", async (req, res) => {
  try {
    const server = makeServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("mcp error", e);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  }
});

app.get("/mcp", (req, res) =>
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null }));
app.delete("/mcp", (req, res) =>
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null }));

app.get("/healthz", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get(["/", "/test"], (req, res) => res.sendFile(path.join(__dirname, "console.html")));

app.listen(PORT, () => console.log("MCP demo server listening on port " + PORT));
```

### `mcp.json` (VS Code client config)

```json
{
  "servers": {
    "contoso-tools": {
      "type": "http",
      "url": "https://<APP_NAME>.azurewebsites.net/mcp"
    }
  }
}
```

### `agent.mjs` (dependency-free fallback client)

```javascript
#!/usr/bin/env node
/*
 * Dependency-free MCP demo client. Requires Node 18+ (built-in fetch).
 *   node agent.mjs
 *   node agent.mjs --url https://<app>.azurewebsites.net/mcp
 */

const argUrl = process.argv.indexOf("--url");
const URL_ = argUrl > -1 ? process.argv[argUrl + 1]
                         : "https://<APP_NAME>.azurewebsites.net/mcp";

const C = {
  r: "\x1b[0m", dim: "\x1b[90m", b: "\x1b[1m",
  grn: "\x1b[32m", red: "\x1b[31m", yel: "\x1b[33m", cyn: "\x1b[36m"
};

let nextId = 1;

async function rpc(method, params) {
  const res = await fetch(URL_, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream"
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params })
  });

  const raw = await res.text();
  let payload = raw;
  const sse = raw.match(/^data:\s*(.+)$/m);
  if (sse) payload = sse[1];

  let json = null;
  try { json = JSON.parse(payload); } catch { /* non-JSON body */ }

  return { status: res.status, json, raw };
}

async function callTool(name, args) {
  process.stdout.write("\n" + C.cyn + "-> " + name + C.r + " " +
                       C.dim + JSON.stringify(args) + C.r + "\n");

  let r;
  try {
    r = await rpc("tools/call", { name, arguments: args });
  } catch (e) {
    console.log("   " + C.red + "NETWORK FAILURE" + C.r + " " + e.message);
    if (/certificate|self.signed|UNABLE_TO_VERIFY/i.test(e.message)) {
      console.log("   " + C.yel +
        "TLS trust problem - set NODE_EXTRA_CA_CERTS to the inspection CA." + C.r);
    }
    return;
  }

  if (r.status === 403) {
    console.log("   " + C.red + C.b + "BLOCKED" + C.r +
                C.red + "  (HTTP 403 - refused in-network by Global Secure Access)" + C.r);
    return;
  }
  if (r.status >= 400 || !r.json) {
    console.log("   " + C.yel + "UNEXPECTED (HTTP " + r.status + ")" + C.r);
    return;
  }
  if (r.json.error) {
    console.log("   " + C.yel + "MCP ERROR " + JSON.stringify(r.json.error) + C.r);
    return;
  }

  const text = (r.json.result?.content ?? []).map(c => c.text).join("\n");
  console.log("   " + C.grn + "ALLOWED" + C.r + C.dim + "  (HTTP 200)" + C.r);
  console.log(text.split("\n").map(l => "   " + C.dim + l + C.r).join("\n"));
}

async function main() {
  console.log("\n" + C.b + "MCP demo agent" + C.r);
  console.log(C.dim + "endpoint: " + URL_ + C.r);

  const init = await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "mcp-demo-agent", version: "1.0.0" }
  });
  if (init.status !== 200) {
    console.log(C.red + "initialize failed: HTTP " + init.status + C.r);
    process.exit(1);
  }
  console.log(C.grn + "connected" + C.r);

  const list = await rpc("tools/list", {});
  const tools = list.json?.result?.tools ?? [];
  console.log(C.dim + "discovered " + tools.length + " tools: " +
              tools.map(t => t.name).join(", ") + C.r);

  await callTool("get_server_health", {});
  await callTool("list_accounts", {});
  await callTool("get_account_balance", { accountId: "ACC-1001" });
  await callTool("export_customer_pii", { count: 3 });

  console.log("\nExpected: first three " + C.grn + "ALLOWED" + C.r +
              ", export_customer_pii " + C.red + "BLOCKED" + C.r + ".\n");
}

main().catch(e => { console.error(C.red + "fatal: " + e.message + C.r); process.exit(1); });
```

### `console.html`

A browser test console with four tool cards, a "Run all tools" button, and a log pane showing ALLOWED / BLOCKED per call. It posts to `/mcp` with
`Accept: application/json, text/event-stream` and parses the SSE `data:` line.

> MCP **cannot** be tested from the browser address bar — a GET to `/mcp` returns 405 by design. The console exists so the protocol can be exercised from the browser, which ensures traffic traverses GSA exactly as the agent's would.

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Firewall Test Console</title>
<style>
  :root{
    --bg:#0f1117; --panel:#171a23; --line:#262b38; --txt:#e6e9f0;
    --dim:#9aa4b8; --ok:#3fb950; --warn:#d29922; --bad:#f85149; --acc:#58a6ff;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font:14px/1.5 "Segoe UI",system-ui,sans-serif}
  header{padding:20px 24px;border-bottom:1px solid var(--line);
         display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
  h1{margin:0;font-size:18px;font-weight:600}
  .ep{color:var(--dim);font:12px ui-monospace,Consolas,monospace}
  main{display:grid;grid-template-columns:minmax(340px,1fr) minmax(360px,1fr);
       gap:18px;padding:20px 24px;align-items:start}
  @media(max-width:900px){main{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);
        border-radius:10px;padding:14px 16px;margin-bottom:12px}
  .card h3{margin:0 0 4px;font-size:14px;display:flex;align-items:center;gap:8px}
  .card p{margin:0 0 10px;color:var(--dim);font-size:12.5px}
  .tag{font-size:10.5px;letter-spacing:.4px;text-transform:uppercase;
       padding:2px 7px;border-radius:999px;font-weight:600}
  .t-ok{background:rgba(63,185,80,.15);color:var(--ok)}
  .t-lo{background:rgba(88,166,255,.15);color:var(--acc)}
  .t-md{background:rgba(210,153,34,.15);color:var(--warn)}
  .t-hi{background:rgba(248,81,73,.15);color:var(--bad)}
  button{background:#21262d;color:var(--txt);border:1px solid #30363d;
         border-radius:6px;padding:7px 14px;font-size:13px;cursor:pointer}
  button:hover{background:#30363d;border-color:#8b949e}
  button.primary{background:#1f6feb;border-color:#1f6feb}
  button.primary:hover{background:#388bfd}
  input{background:#0d1117;color:var(--txt);border:1px solid #30363d;
        border-radius:6px;padding:6px 9px;font-size:13px;width:120px;margin-right:8px}
  #log{background:#0a0c10;border:1px solid var(--line);border-radius:10px;
       padding:14px;height:70vh;overflow:auto;
       font:12.5px/1.55 ui-monospace,Consolas,monospace;white-space:pre-wrap}
  .l-ok{color:var(--ok)} .l-bad{color:var(--bad)} .l-dim{color:var(--dim)}
  .l-acc{color:var(--acc)} .l-warn{color:var(--warn)}
  .bar{display:flex;gap:10px;margin-bottom:12px;align-items:center}
</style>
</head>
<body>
<header>
  <h1>MCP Firewall Test Console</h1>
  <span class="ep">endpoint: <b id="ep"></b></span>
</header>

<main>
  <section>
    <div class="bar">
      <button class="primary" onclick="runAll()">Run all tools</button>
      <button onclick="clearLog()">Clear log</button>
    </div>

    <div class="card">
      <h3>get_server_health <span class="tag t-ok">benign</span></h3>
      <p>Diagnostic only. Should always be allowed.</p>
      <button onclick="call('get_server_health',{})">Call</button>
    </div>

    <div class="card">
      <h3>list_accounts <span class="tag t-lo">low risk</span></h3>
      <p>Lists account ids and owners. No financial detail.</p>
      <button onclick="call('list_accounts',{})">Call</button>
    </div>

    <div class="card">
      <h3>get_account_balance <span class="tag t-md">sensitive</span></h3>
      <p>Returns a balance for one account.</p>
      <input id="acct" value="ACC-1001">
      <button onclick="call('get_account_balance',{accountId:document.getElementById('acct').value})">Call</button>
    </div>

    <div class="card">
      <h3>export_customer_pii <span class="tag t-hi">high risk</span></h3>
      <p>Bulk PII export incl. SSN and DOB. <b>This is the tool the GSA MCP firewall should block.</b></p>
      <input id="cnt" value="3" style="width:70px">
      <button onclick="call('export_customer_pii',{count:parseInt(document.getElementById('cnt').value||'3',10)})">Call</button>
    </div>
  </section>

  <section>
    <div id="log"></div>
  </section>
</main>

<script>
const EP = location.origin + "/mcp";
document.getElementById("ep").textContent = EP;

const logEl = document.getElementById("log");
function line(txt, cls){
  const s = document.createElement("div");
  if(cls) s.className = cls;
  s.textContent = txt;
  logEl.appendChild(s);
  logEl.scrollTop = logEl.scrollHeight;
}
function clearLog(){ logEl.innerHTML = ""; }
function ts(){ return new Date().toLocaleTimeString(); }

async function rpc(method, params, id){
  const r = await fetch(EP, {
    method:"POST",
    headers:{ "Content-Type":"application/json",
              "Accept":"application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc:"2.0", id, method, params })
  });
  const raw = await r.text();
  let body = raw;
  // streamable http may answer as SSE
  const m = raw.match(/^data:\s*(.+)$/m);
  if(m) body = m[1];
  let json = null;
  try { json = JSON.parse(body); } catch(e){}
  return { status:r.status, json, raw };
}

async function call(tool, args){
  line("");
  line("[" + ts() + "] -> " + tool + "  " + JSON.stringify(args), "l-acc");
  try{
    // stateless server expects initialize per logical session
    await rpc("initialize", {
      protocolVersion:"2024-11-05",
      capabilities:{},
      clientInfo:{ name:"browser-test-console", version:"1.0.0" }
    }, 1);

    const res = await rpc("tools/call", { name:tool, arguments:args }, 2);

    if(res.status >= 400 || !res.json){
      line("   BLOCKED or FAILED  (HTTP " + res.status + ")", "l-bad");
      line("   " + res.raw.slice(0,600), "l-dim");
      return;
    }
    if(res.json.error){
      line("   ERROR: " + JSON.stringify(res.json.error), "l-warn");
      return;
    }
    const txt = (res.json.result && res.json.result.content || [])
                  .map(c => c.text).join("\n");
    line("   ALLOWED  (HTTP 200)", "l-ok");
    line(txt.split("\n").map(l => "   " + l).join("\n"), "l-dim");
  }catch(e){
    line("   NETWORK BLOCKED / FAILED: " + e.message, "l-bad");
    line("   (a hard network failure here is what a GSA block looks like to the browser)", "l-dim");
  }
}

async function runAll(){
  clearLog();
  line("Running all four tools against " + EP, "l-acc");
  await call("get_server_health", {});
  await call("list_accounts", {});
  await call("get_account_balance", { accountId:"ACC-1001" });
  await call("export_customer_pii", { count:3 });
  line("");
  line("Done. Expect the first three ALLOWED and export_customer_pii BLOCKED.", "l-acc");
}

line("Ready. Click \"Run all tools\" to exercise the MCP server through Global Secure Access.", "l-dim");
</script>
</body>
</html>
```

> **Note on the private-access variant.** If you also stand up a copy of this server on an internal host reached through Private Access, change the wording on that copy. GSA security profiles are not evaluated on that path, so all four tools return 200 and nothing is blocked — see [§2.1](#21-the-mcp-server-must-be-reachable-over-the-public-internet). That copy is still useful for showing what each tool exposes, but it should state plainly that the firewall is not in effect and link to the internet-facing instance for the block.

---

## Licence and data notice

All account and customer data in this demo is **synthetic**. SSNs use the reserved
`555-xx-xxxx` range and email addresses use the reserved `.invalid` TLD. No real
customer information is present or required.



