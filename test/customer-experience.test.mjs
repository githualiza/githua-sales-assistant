import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderCustomerDashboard } from "../src/customer-experience.js";
const data={firstName:"Test",organization:"Test Co",role:"owner",counts:{leads:3,conversations:2,won:1},drafts:1,pending:2,preparations:1};
test("dashboard has functional navigation and contextual help controls",()=>{
 const page=renderCustomerDashboard(data);
 for(const link of ["/assistant","/documents","/deliveries","/leads","/tasks"])assert.ok(page.includes('href="'+link+'"'));
 assert.match(page,/data-guide="quotation"/);
 assert.match(page,/data-guide="approval"/);
 assert.match(page,/id="guide-panel"/);
 assert.match(page,/aria-expanded="false"/);
 assert.match(page,/3<\/strong><span>Total leads/);
 assert.match(page,/1 draft document/);
});
test("dashboard escapes untrusted user and organization data",()=>{
 const page=renderCustomerDashboard({...data,firstName:'<img src=x onerror=alert(1)>',organization:'"><script>alert(1)</script>'});
 assert.doesNotMatch(page,/<img src=x/);
 assert.doesNotMatch(page,/<script>alert/);
 assert.match(page,/&lt;img/);
 assert.match(page,/&lt;script&gt;/);
});
test("original dashboard is restored and optional help is staging-only",()=>{
 const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
 const dashboard=source.slice(source.indexOf("async function dashboard("),source.indexOf("\nasync function ",source.indexOf("async function dashboard(")+20));
 assert.match(dashboard,/requireSession\(request, env\)/);
 assert.match(dashboard,/env\.STAGING_ENVIRONMENT === "true"/);
 assert.match(dashboard,/githua-sales-assistant-staging\.githualiza\.workers\.dev/);
 assert.doesNotMatch(dashboard,/renderCustomerDashboard/);
 assert.match(dashboard,/githua-guide-open/);
});
test("customer experience preview is read-only and makes no outbound calls",()=>{
 const source=readFileSync(new URL("../src/customer-experience.js",import.meta.url),"utf8");
 assert.doesNotMatch(source,/\bfetch\s*\(|\bXMLHttpRequest\b|\bPOST\b|\bPATCH\b/);
 assert.doesNotMatch(source,/sendEmail|smtp|queue\.send/);
});
