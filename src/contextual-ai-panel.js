// Staging-only, opt-in assistant panel on authenticated document pages.
// It uses the existing session-checked, read-only /v1/app-assistant endpoint.
export function contextualAiEnabled(request, env) {
 return env.STAGING_ENVIRONMENT === "true" &&
  new URL(request.url).hostname === "githua-sales-assistant-staging.githualiza.workers.dev";
}
export function contextualAiPanel(page) {
 if (!["documents","deliveries"].includes(page)) throw Error("Unsupported page");
 const label=page==="documents"?"Documents":"Delivery Review";
 const fragment = `<style>
.cx-ai-toggle{position:fixed;bottom:18px;right:18px;z-index:105;border:1px solid #efdcff;border-radius:30px;padding:12px 18px;color:#201026;background:linear-gradient(110deg,#ffe7cf,#ddb4f7);font:700 14px system-ui;box-shadow:0 12px 30px #0009;cursor:pointer}
.cx-ai-panel{position:fixed;z-index:106;bottom:16px;right:16px;width:min(425px,calc(100vw - 32px));max-height:min(620px,calc(100dvh - 32px));background:#1a1125;border:1px solid #b99dd0;border-radius:20px;box-shadow:0 20px 65px #000b;display:flex;flex-direction:column;color:#fcf5ff;font:14px/1.5 system-ui}
.cx-ai-panel[hidden]{display:none}.cx-ai-header{display:flex;align-items:center;justify-content:space-between;padding:18px;border-bottom:1px solid #6d557d}.cx-ai-header strong{font:23px Georgia,serif}.cx-ai-close{color:#fff;background:#342343;border:1px solid #ba9cce;border-radius:9px;padding:7px 10px;cursor:pointer}
.cx-ai-messages{padding:15px 18px;overflow-y:auto;min-height:120px;max-height:320px;display:grid;gap:10px;overflow-wrap:anywhere}
.cx-ai-message{padding:11px 13px;border-radius:12px;background:#322341;white-space:pre-wrap}.cx-ai-message.user{background:#514067}.cx-ai-note{color:#e7d5ee;font-size:12px;padding:9px 18px 0}
.cx-ai-form{padding:14px 18px 18px;display:grid;gap:9px}.cx-ai-form textarea{width:100%;resize:vertical;min-height:74px;max-height:160px;background:#120d18;border:1px solid #a18bb1;color:#fff;border-radius:10px;padding:11px;font:inherit}
.cx-ai-form button{color:#26112e;background:#eed4ff;border:1px solid #f8e3ff;padding:10px;border-radius:10px;font-weight:700;cursor:pointer}.cx-ai-form button:disabled{opacity:.6;cursor:wait}
.cx-ai-panel :focus-visible,.cx-ai-toggle:focus-visible{outline:3px solid #ffe7be;outline-offset:3px}
</style>
<button class="cx-ai-toggle" type="button" id="cx-ai-open" aria-controls="cx-ai-panel" aria-expanded="false">✧ Ask AI about this step</button>
<section class="cx-ai-panel" id="cx-ai-panel" aria-label="Contextual AI assistance" hidden>
<div class="cx-ai-header"><strong>Ask AI · __LABEL__</strong><button id="cx-ai-close" class="cx-ai-close" type="button" aria-label="Close AI panel">✕</button></div>
<p class="cx-ai-note">Optional help. No document details are sent automatically. AI can explain and draft, but cannot approve or send anything.</p>
<div id="cx-ai-messages" class="cx-ai-messages" role="log" aria-live="polite"><div class="cx-ai-message">What would you like help with in __LABEL__?</div></div>
<form id="cx-ai-form" class="cx-ai-form"><label for="cx-ai-query">Your question</label><textarea id="cx-ai-query" maxlength="4000" placeholder="Ask about a document or next step…" required></textarea><button type="submit" id="cx-ai-send">Ask AI</button><span id="cx-ai-feedback" role="status"></span></form></section>
<script nonce="cx-contextual-ai">
(()=>{
const panel=document.getElementById("cx-ai-panel"),toggle=document.getElementById("cx-ai-open"),close=document.getElementById("cx-ai-close"),form=document.getElementById("cx-ai-form"),query=document.getElementById("cx-ai-query"),messages=document.getElementById("cx-ai-messages"),send=document.getElementById("cx-ai-send"),feedback=document.getElementById("cx-ai-feedback");
let returnFocus=null,history=[],working=false;
function show(){returnFocus=document.activeElement;panel.hidden=false;toggle.setAttribute("aria-expanded","true");query.focus()}
function hide(){if(working)return;panel.hidden=true;toggle.setAttribute("aria-expanded","false");if(returnFocus&&returnFocus.focus)returnFocus.focus()}
toggle.addEventListener("click",show);close.addEventListener("click",hide);
document.addEventListener("keydown",event=>{if(event.key==="Escape"&&!panel.hidden)hide()});
function append(kind,value){const node=document.createElement("div");node.className="cx-ai-message"+(kind==="user"?" user":"");node.textContent=value;messages.appendChild(node);messages.scrollTop=messages.scrollHeight}
form.addEventListener("submit",async event=>{
event.preventDefault();if(working)return;const value=query.value.trim();if(!value)return;
const outgoing=[...history,{role:"user",content:value}].slice(-10);
working=true;send.disabled=true;feedback.textContent="Thinking…";append("user",value);query.value="";
try{
const response=await fetch("/v1/app-assistant",{method:"POST",headers:{"content-type":"application/json"},credentials:"same-origin",body:JSON.stringify({messages:outgoing})});
const result=await response.json();if(!response.ok||typeof result.answer!=="string")throw Error(result.error||"AI is unavailable");
append("assistant",result.answer);history=[...outgoing,{role:"assistant",content:result.answer}].slice(-10);feedback.textContent="Please review AI suggestions before acting.";
}catch(error){append("assistant",error.message||"Could not get an answer.");feedback.textContent="You can try again."}
finally{working=false;send.disabled=false}
});
})();
</script>`;
 return fragment.replaceAll("__LABEL__",label);
}
