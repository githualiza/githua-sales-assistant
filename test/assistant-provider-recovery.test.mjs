import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
const staging=readFileSync(new URL("../.github/workflows/deploy-staging.yml",import.meta.url),"utf8");
const start=source.indexOf("async function browserAssistant(request,env)");
const stop=source.indexOf("\nfunction validateMessages",start);
const handler=source.slice(start,stop);
test("staging deploy verifies AI provider secret without exposing its value",()=>{
 assert.match(staging,/for \(const name of \['SESSION_SECRET','AUTH0_CLIENT_SECRET','OPENROUTER_API_KEY'\]\)/);
 assert.doesNotMatch(staging,/echo.*OPENROUTER_API_KEY/);
});
test("assistant fallback tries a different model on provider error or empty response",()=>{
 assert.match(handler,/for\(const model of \[\.\.\.new Set\(\[primaryModel,fallbackModel\]\)\]\)/);
 assert.match(handler,/const candidate=assistantText\(current\)/);
 assert.match(handler,/if\(!candidate\)/);
 assert.match(handler,/if\(\[401,403\]\.includes\(code\)\)break/);
});
test("missing credentials returns safe error, and provider errors do not leak secrets",()=>{
 assert.match(handler,/if\(!env\.OPENROUTER_API_KEY\)return json/);
 assert.match(source,/error\.providerStatus = response\.status/);
 assert.match(handler,/status:code\|\|"network_or_timeout"/);
 assert.doesNotMatch(handler,/console\.(warn|error)\([^\n]*OPENROUTER_API_KEY/);
});
test("existing session and organization authorization maintained",()=>{
 assert.match(handler,/requireSession\(request,env\)/);
 assert.match(handler,/activeMembership\(s,env\)/);
 assert.match(handler,/ASSISTANT_ROLES\.has\(m\.role\)/);
 assert.match(source,/Luminous%20Silk%20Ribbons/);
});
