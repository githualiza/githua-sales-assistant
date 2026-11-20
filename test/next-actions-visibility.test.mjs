import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderNextActions } from "../src/next-actions.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
test("Next Actions is a visible staging-only sidebar link and assistant shortcut",()=>{
 const start=source.indexOf("async function dashboard(");
 const end=source.indexOf("\nasync function ",start+30);
 const dash=source.slice(start,end);
 assert.match(dash,/<nav class="nav">\$\{showContextHelp \?/);
 assert.match(dash,/class="next-actions-nav" href="\/next-actions"/);
 assert.match(dash,/class="next-actions-cta" href="\/next-actions"/);
 assert.match(dash,/class="githua-guide-button"/);
 assert.match(dash,/Luminous%20Silk%20Ribbons/);
});
test("empty next actions page recommends real, usable next steps",()=>{
 const page=renderNextActions({actions:[],partial:false,taskAllowed:true,leadAllowed:true,docAllowed:true});
 assert.match(page,/Nothing needs urgent attention right now/);
 assert.match(page,/Other actions you can take/);
 for(const href of ["/tasks","/leads","/assistant","/documents"])assert.ok(page.includes('href="'+href+'"'),href);
 assert.doesNotMatch(page,/No urgent items found in the available workspace records/);
});
test("other actions honor read permissions and are visible with outstanding items",()=>{
 const noRights=renderNextActions({actions:[],taskAllowed:false,leadAllowed:false,docAllowed:false});
 for(const href of ["/tasks","/leads","/documents","/assistant"]) assert.doesNotMatch(noRights,new RegExp('href="'+href+'"'));
 const populated=renderNextActions({actions:[{kind:"task",id:"abcd",title:"Follow up",detail:"Priority: high"}]});
 assert.match(populated,/Other actions you can take/);
 assert.match(populated,/Why this matters and what to do next/);
});
test("existing production appearance and email safety are preserved",()=>{
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
 assert.match(source,/if\(!isStagingSetupRequest\(request,env\)\)return json/);
 assert.match(source,/githua-guide-panel/);
});
