import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {actionExplanation} from "../src/action-explanations.js";
import {prioritizeWorkspace,renderNextActions} from "../src/next-actions.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");

test("overdue and upcoming tasks have specific explanations",()=>{
 const overdue=actionExplanation({kind:"task",id:"abc-123",detail:"Past due — check your deadline"});
 assert.match(overdue.reason,/due date is already past/);
 assert.equal(overdue.href,"/tasks/abc-123");
 const soon=actionExplanation({kind:"task",id:"2",detail:"Due within 48 hours"});
 assert.match(soon.reason,/48 hours/);
});
test("document review and lead next steps do not imply completed actions",()=>{
 const document=actionExplanation({kind:"document",detail:"Waiting for authorized document review"});
 assert.equal(document.href,"/documents");
 assert.match(document.next,/authorized reviewer/);
 const lead=actionExplanation({kind:"lead",id:"abc-123",detail:"New enquiry — review and plan contact"});
 assert.equal(lead.href,"/leads/abc-123");
 assert.match(lead.next,/No message will be sent automatically/);
});
test("unknown or malformed IDs only navigate to valid workspace pages",()=>{
 assert.equal(actionExplanation({kind:"task",id:"../../admin",detail:"Priority: high"}).href,"/tasks");
 assert.equal(actionExplanation({kind:"lead",id:"javascript:alert(1)"}).href,"/leads");
 assert.equal(actionExplanation({kind:"unknown"}).href,"/next-actions");
});
test("explanations escape untrusted titles and show native disclosures",()=>{
 const page=renderNextActions({actions:[{kind:"task",id:"valid",title:'<img src=x onerror=alert(1)>',detail:"Priority: high"}]});
 assert.match(page,/<details><summary>Why this matters and what to do next/);
 assert.match(page,/Why suggested:/);
 assert.match(page,/Suggested next step:/);
 assert.match(page,/href="\/tasks\/valid"/);
 assert.match(page,/&lt;img/);
 assert.doesNotMatch(page,/<img src=x/);
 assert.doesNotMatch(page,/<script|fetch\(/);
});
test("original staging-only route and approved dashboard remain untouched",()=>{
 assert.match(source,/if\(!isStagingSetupRequest\(request,env\)\)return json/);
 assert.match(source,/Luminous%20Silk%20Ribbons/);
 assert.match(source,/githua-guide-panel/);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
