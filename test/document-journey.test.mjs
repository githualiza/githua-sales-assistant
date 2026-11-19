import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {isStagingJourney,workflowGuide} from "../src/document-journey.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
test("journey only in staging",()=>{
 assert.equal(isStagingJourney(new Request("https://githua-sales-assistant-staging.githualiza.workers.dev/documents"),{STAGING_ENVIRONMENT:"true"}),true);
 assert.equal(isStagingJourney(new Request("https://sales.githuaaisystems.com/documents"),{STAGING_ENVIRONMENT:"true"}),false);
 assert.equal(isStagingJourney(new Request("https://githua-sales-assistant-staging.githualiza.workers.dev/documents"),{}),false);
});
test("accessible help on each stage never offers sending",()=>{
 for(const stage of ["assistant","documents","deliveries"]){
  const markup=workflowGuide(stage);
  assert.match(markup,/Show me how/);
  assert.match(markup,/details>/);
  assert.match(markup,/does not send an email/);
  assert.doesNotMatch(markup,/form action=|<script|onclick=/);
 }
});
test("journey surfaces use existing route guards and no separate data stores",()=>{
 assert.match(source,/isStagingJourney\(request,env\)/);
 assert.match(source,/workflowGuide\("documents"\)/);
 assert.match(source,/workflowGuide\("assistant"\)/);
 assert.match(source,/workflowGuide\("deliveries"\)/);
 assert.match(source,/id="staging-workflow-marker"/);
 assert.match(source,/Next: Review saved documents/);
 assert.match(source,/Preparation saved — next: Open Delivery Review/);
});
test("production home visuals and document approvals unchanged",()=>{
 assert.match(source,/Luminous%20Silk%20Ribbons/);
 assert.match(source,/githua-guide-panel/);
 assert.match(source,/if\(!\["owner","admin"\]\.includes\(a\.membership\.role\)\)/);
});
