import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {prioritizeWorkspace,renderNextActions} from "../src/next-actions.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
test("priorities are deterministic and capped",()=>{
 const now=new Date("2026-11-20T12:00:00Z");
 const items=prioritizeWorkspace({tasks:[
  {id:"1",title:"Normal",status:"open",priority:"normal"},
  {id:"2",title:"Overdue",status:"open",priority:"low",due_at:"2026-11-19T12:00:00Z"},
  {id:"3",title:"Finished",status:"completed",priority:"urgent"},
  {id:"4",title:"Soon",status:"in_progress",priority:"normal",due_at:"2026-11-21T12:00:00Z"}
 ],documents:[{id:"5",reference:"Q-1",status:"ready_for_review"}],leads:[{id:"6",name:"Lead",status:"new"}]},now);
 assert.equal(items[0].title,"Overdue");
 assert.equal(items[1].title,"Soon");
 assert.ok(items.some(x=>x.title==="Q-1"));
 assert.ok(!items.some(x=>x.title==="Finished"));
 assert.ok(items.length<=8);
});
test("no unsupported navigation, script injection, or automatic actions",()=>{
 const markup=renderNextActions({actions:[{kind:"task",title:'<img src=x onerror=alert(1)>',detail:"Review",href:"/tasks"}]});
 assert.doesNotMatch(markup,/<img src=x/);
 assert.match(markup,/&lt;img/);
 assert.match(markup,/read-only/);
 assert.doesNotMatch(markup,/<script|fetch\(|form action=/);
});
test("page is gated by staging hostname, session and organization membership",()=>{
 const start=source.indexOf("async function nextActionsPage("),end=source.indexOf("\nasync function dashboard(",start);
 const page=source.slice(start,end);
 assert.match(page,/isStagingSetupRequest\(request,env\)/);
 assert.match(page,/requireSession\(request,env\)/);
 assert.match(page,/activeMembership\(session,env\)/);
 assert.match(page,/TASK_READ_ROLES\.has\(membership.role\)/);
 assert.match(page,/LEAD_READ_ROLES\.has\(membership.role\)/);
 assert.match(page,/ASSISTANT_ROLES\.has\(membership.role\)/);
 assert.match(page,/organization_id=\?/);
 assert.match(page,/Promise\.allSettled/);
 assert.match(source,/url.pathname === "\/next-actions"/);
 assert.match(source,/href="\/next-actions"/);
});
test("original dashboard design and no customer sends preserved",()=>{
 assert.match(source,/Luminous%20Silk%20Ribbons/);
 assert.match(source,/githua-guide-panel/);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
