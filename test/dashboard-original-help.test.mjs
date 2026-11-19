import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
const dashboard=source.slice(source.indexOf("async function dashboard(request, env)"),source.indexOf("\nasync function ",source.indexOf("async function dashboard(request, env)")+30));
test("original dashboard appearance and navigation stay in place",()=>{
 assert.match(dashboard,/Luminous%20Silk%20Ribbons%20in%20Purple%20and%20Gold/);
 assert.match(dashboard,/premium-assistant/);
 assert.match(dashboard,/class="app"/);
 assert.match(dashboard,/href="\/leads"/);
 assert.match(dashboard,/href="\/documents"/);
 assert.doesNotMatch(dashboard,/renderCustomerDashboard\(/);
});
test("Show me how is restricted to staging and production HTML retains original CSP",()=>{
 assert.match(dashboard,/env\.STAGING_ENVIRONMENT === "true"/);
 assert.match(dashboard,/githua-sales-assistant-staging\.githualiza\.workers\.dev/);
 assert.match(dashboard,/guideWidget.*?showContextHelp/s);
 assert.match(dashboard,/nonce-githua-help-only/);
 assert.match(dashboard,/showContextHelp \? \{"content-security-policy":/);
});
test("help overlay has useful close controls and preserves dashboard",()=>{
 assert.match(dashboard,/githua-guide-panel/);
 assert.match(dashboard,/data-help="documents"/);
 assert.match(dashboard,/data-help="delivery"/);
 assert.match(dashboard,/e\.key==="Escape"/);
 assert.doesNotMatch(dashboard,/sendEmail|smtp|queue\.send/);
});
