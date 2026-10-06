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
