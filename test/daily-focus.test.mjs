import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dailyFocusModel, renderDailyFocus } from "../src/daily-focus.js";
import { prioritizeWorkspace, renderNextActions } from "../src/next-actions.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");

test("daily focus shows top three ranked recommendations in order",()=>{
 const actions=prioritizeWorkspace({tasks:[
  {id:"one",title:"Routine",status:"open",priority:"normal"},
  {id:"two",title:"Past due",status:"open",priority:"normal",due_at:"2026-11-18T12:00:00Z"},
  {id:"three",title:"High priority",status:"open",priority:"high"},
  {id:"four",title:"Due soon",status:"open",priority:"low",due_at:"2026-11-21T12:00:00Z"}
 ],leads:[{id:"lead",name:"New enquiry",status:"new"}]},new Date("2026-11-20T12:00:00Z"));
 const model=dailyFocusModel(actions);
 assert.equal(model.items.length,3);
 assert.deepEqual(model.items.map(a=>a.title),["Past due","Due soon","High priority"]);
 assert.equal(model.overdue,1);
 const page=renderDailyFocus(actions);
 assert.ok(page.indexOf("Past due")<page.indexOf("Due soon"));
 assert.ok(page.indexOf("Due soon")<page.indexOf("High priority"));
 assert.ok(!page.includes("Routine"));
});
test("focus list renders an actionable empty state",()=>{
 const page=renderNextActions({actions:[],taskAllowed:true,leadAllowed:true,docAllowed:true});
 assert.match(page,/Start with these three/);
 assert.match(page,/No pressing priorities in this view/);
 assert.match(page,/Other actions you can take/);
 for(const path of ["/tasks","/leads","/assistant","/documents"])assert.ok(page.includes('href="'+path+'"'));
});
test("HTML is escaped and links are restricted to existing workspace pages",()=>{
 const result=renderDailyFocus([{kind:"task",title:'<img src=x onerror=alert(1)>',detail:"Urgent",href:"javascript:alert(1)"}],true);
 assert.match(result,/&lt;img/);
 assert.doesNotMatch(result,/<img src=x|javascript:alert|<script/);
 assert.match(result,/href="\/tasks"/);
 assert.match(result,/view may be incomplete/);
});
test("no server writes and staging visibility remain guarded",()=>{
 assert.match(source,/if\(!isStagingSetupRequest\(request,env\)\)return json/);
 assert.match(source,/class="next-actions-nav" href="\/next-actions"/);
 assert.match(source,/Luminous%20Silk%20Ribbons/);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
