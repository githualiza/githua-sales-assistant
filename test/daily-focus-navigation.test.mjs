import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {renderDailyFocus} from "../src/daily-focus.js";
import {renderNextActions} from "../src/next-actions.js";
const index=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");

test("Daily Focus always renders with a stable anchor including an empty state",()=>{
 const empty=renderDailyFocus([]);
 assert.match(empty,/id="daily-focus"/);
 assert.match(empty,/Start with these three/);
 assert.match(empty,/No pressing priorities in this view/);
 const populated=renderNextActions({actions:[{kind:"task",id:"x",title:"Task X",detail:"Priority: high"}]});
 assert.match(populated,/id="daily-focus"/);
 assert.match(populated,/Task X/);
});
test("dashboard offers prominent Daily Focus navigation in staging only",()=>{
 const start=index.indexOf("async function dashboard("),end=index.indexOf("\nasync function ",start+30);
 const dashboard=index.slice(start,end);
 assert.match(dashboard,/\$\{showContextHelp \? '<a class="daily-focus-nav" href="\/daily-focus"/);
 assert.match(dashboard,/\$\{showContextHelp \? '<a class="daily-focus-cta" href="\/daily-focus"/);
 assert.match(dashboard,/href="\/daily-focus">Open Daily Focus/);
 assert.match(dashboard,/Luminous%20Silk%20Ribbons/);
});
test("direct Daily Focus route uses staging guard and existing authorized page",()=>{
 assert.match(index,/url\.pathname === "\/daily-focus"\) return isStagingSetupRequest\(request,env\) \? redirect\("\/next-actions#daily-focus"\) : json\(\{error:"Not found"\},404\)/);
 assert.match(index,/async function nextActionsPage\(request,env\)\{\s*if\(!isStagingSetupRequest\(request,env\)\)/);
 assert.match(index,/const session=await requireSession\(request,env\)/);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
