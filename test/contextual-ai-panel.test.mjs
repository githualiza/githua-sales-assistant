import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { contextualAiEnabled, contextualAiPanel } from "../src/contextual-ai-panel.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
test("AI panel only enabled on explicit staging hostname and flag",()=>{
 const staging=new Request("https://githua-sales-assistant-staging.githualiza.workers.dev/documents");
 assert.equal(contextualAiEnabled(staging,{STAGING_ENVIRONMENT:"true"}),true);
 assert.equal(contextualAiEnabled(staging,{}),false);
 assert.equal(contextualAiEnabled(new Request("https://sales.githuaaisystems.com/documents"),{STAGING_ENVIRONMENT:"true"}),false);
});
test("panel can be closed and explains limitations",()=>{
 for(const stage of ["documents","deliveries"]){
  const markup=contextualAiPanel(stage);
  assert.match(markup,/id="cx-ai-open"/);
  assert.match(markup,/id="cx-ai-close"/);
  assert.match(markup,/No document details are sent automatically/);
  assert.match(markup,/cannot approve or send/);
  assert.match(markup,/event.key==="Escape"/);
  assert.match(markup,/textContent=value/);
  assert.match(markup,/fetch\("\/v1\/app-assistant"/);
  assert.match(markup,/method:"POST"/);
  assert.match(markup,/credentials:"same-origin"/);
 }
});
test("contextual assistant uses existing protected route and does not alter document actions",()=>{
 assert.match(source,/contextualAiPanel\("documents"\)/);
 assert.match(source,/contextualAiPanel\("deliveries"\)/);
 assert.match(source,/script-src 'nonce-document-centre-ui' 'nonce-cx-contextual-ai'/);
 assert.match(source,/script-src 'nonce-delivery-review-ui' 'nonce-cx-contextual-ai'/);
 assert.match(source,/async function browserAssistant\(request,env\)\{/);
 assert.match(source,/if\(!s\?\.uid\)return json\(\{error:"Unauthorized"\},401\)/);
 assert.match(source,/Luminous%20Silk%20Ribbons/);
});
