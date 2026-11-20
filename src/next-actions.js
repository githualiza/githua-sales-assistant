import { actionExplanation } from "./action-explanations.js";
// Read-only, deterministic next-action suggestions for the staging workspace.
// Each recommendation links to an existing page; suggestions never change records.
const escapeHtmlLocal=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
export function prioritizeWorkspace({tasks=[],documents=[],leads=[]},now=new Date()){
 const today=now.getTime();
 const actions=[];
 for(const t of tasks){
  if(!["open","in_progress"].includes(t.status))continue;
  const date=t.due_at?Date.parse(t.due_at):NaN;
  const overdue=Number.isFinite(date)&&date<today;
  const soon=Number.isFinite(date)&&date>=today&&date-today<=48*3600000;
  const rank=overdue?0:soon?1:t.priority==="urgent"?2:t.priority==="high"?3:5;
  actions.push({rank,kind:"task",title:t.title||"Untitled task",detail:overdue?"Past due — check your deadline":soon?"Due within 48 hours":"Priority: "+(t.priority||"normal"),href:"/tasks",id:t.id||"",due:Number.isFinite(date)?date:Infinity});
 }
 for(const d of documents){
  if(d.status==="ready_for_review")actions.push({rank:1,kind:"document",title:d.reference||"Document awaiting review",detail:"Waiting for authorized document review",href:"/documents",id:d.id||"",due:Infinity});
  if(d.status==="rejected")actions.push({rank:3,kind:"document",title:d.reference||"Document needs revision",detail:"Rejected — review feedback and revise",href:"/documents",id:d.id||"",due:Infinity});
 }
 for(const l of leads){
  if(l.status==="new")actions.push({rank:4,kind:"lead",title:l.name||"New lead",detail:"New enquiry — review and plan contact",href:"/leads",id:l.id||"",due:Infinity});
 }
 return actions.sort((a,b)=>a.rank-b.rank||a.due-b.due||String(a.id).localeCompare(String(b.id))).slice(0,8);
}
export function renderNextActions({actions=[],partial=false,taskAllowed=true,leadAllowed=true,docAllowed=true}){
 const items=actions.map(a=>{
  const guide=actionExplanation(a);
  return '<li><span class="priority-tag">'+escapeHtmlLocal(a.kind)+'</span> <strong>'+escapeHtmlLocal(a.title)+'</strong><span class="priority-desc">'+escapeHtmlLocal(a.detail)+'</span><details><summary>Why this matters and what to do next</summary><p><b>Why suggested:</b> '+escapeHtmlLocal(guide.reason)+'</p><p><b>Suggested next step:</b> '+escapeHtmlLocal(guide.next)+'</p></details><a href="'+escapeHtmlLocal(guide.href)+'">'+escapeHtmlLocal(guide.link)+' →</a></li>';
 }).join("");
 const list=items||'<li><strong>Nothing needs urgent attention right now</strong><span class="priority-desc">There are no matching open tasks, review requests or new leads in the available workspace data. You can still start something useful below.</span></li>';
 const starters=[
  taskAllowed?'<a href="/tasks">Review or create a task →</a>':"",
  leadAllowed?'<a href="/leads">Review or add a lead →</a>':"",
  docAllowed?'<a href="/assistant">Create a quotation, proposal or budget →</a>':"",
  docAllowed?'<a href="/documents">Review your documents →</a>':""
 ].filter(Boolean).join("");
 const starterSection='<section class="panel starter-panel" aria-label="Other useful actions"><h2>Other actions you can take</h2><p>Choose a starting point even when there is nothing overdue.</p><div class="starter-links">'+starters+'</div></section>';
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Next Actions · Githua Sales Assistant</title><style>
 *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 85% 12%,rgba(166,100,205,.30),transparent 42%),linear-gradient(130deg,#0b0811,#23122c 60%,#100b15);color:#f9eefb;font:15px/1.5 system-ui,sans-serif}main{max-width:870px;margin:auto;padding:38px 22px 80px}a{color:#efd2ff}nav{display:flex;gap:18px;flex-wrap:wrap}h1{font:44px Georgia,serif;margin:30px 0 10px}p{color:#e2d1e9}.panel{margin:24px 0;background:rgba(26,15,36,.79);border:1px solid #846b91;border-radius:22px;padding:20px 24px;box-shadow:0 20px 50px #0005}ul{padding:0;margin:0;list-style:none}li{padding:16px 0;border-bottom:1px solid #60496b}li:last-child{border:0}li strong{display:block;font-size:17px;margin:5px 0}.priority-tag{text-transform:uppercase;letter-spacing:.1em;color:#f3d7af;font-size:11px}.priority-desc{display:block;margin-bottom:9px;color:#dfcfe7}a:focus-visible{outline:3px solid #ffdcaf;outline-offset:3px}details{margin:12px 0}summary{cursor:pointer;font-weight:700;color:#f8e7ff}details p{margin:8px 0}details b{color:#f5dbb5}summary:focus-visible{outline:3px solid #ffdcaf;outline-offset:3px}h2{font:28px Georgia,serif;margin:0 0 8px}.starter-links{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:15px}.starter-links a{border:1px solid #9f86b4;border-radius:12px;background:#35223e;padding:15px;text-decoration:none;font-weight:700}.starter-links a:hover{background:#4c3458}
 </style></head><body><main><nav aria-label="Workspace"><a href="/">← Dashboard</a>${taskAllowed?'<a href="/tasks">Tasks</a>':""}${leadAllowed?'<a href="/leads">Leads</a>':""}${docAllowed?'<a href="/documents">Documents</a>':""}</nav><h1>Your next actions</h1><p>Suggested priorities from your current workspace. Overdue and soon-due tasks come first, followed by documents awaiting review, urgent tasks and new enquiries. Review each suggestion before acting.</p>${partial?'<p role="status">Some workspace information is temporarily unavailable. These suggestions may be incomplete.</p>':""}<section class="panel" aria-label="Prioritized work"><ul>${list}</ul></section>${starterSection}<p>These suggestions are automatic, read-only and do not notify customers, update tasks, approve documents or send emails.</p></main></body></html>`;
}
