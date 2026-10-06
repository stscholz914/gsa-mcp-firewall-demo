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
