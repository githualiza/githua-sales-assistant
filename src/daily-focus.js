// Phase B5: read-only daily focus summary drawn from the same bounded, authorized
// recommendation list as Next Actions. No persistent preferences, writes or sends.
const escapeText=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safeDestination=action=>{
 if(action.kind==="task")return "/tasks";
 if(action.kind==="document")return "/documents";
 if(action.kind==="lead")return "/leads";
 return "/next-actions";
};
export function dailyFocusModel(actions=[],partial=false){
 const limited=actions.slice(0,3);
 const overdue=actions.filter(a=>a.kind==="task"&&a.detail==="Past due — check your deadline").length;
 const review=actions.filter(a=>a.kind==="document"&&a.detail==="Waiting for authorized document review").length;
 const urgent=actions.filter(a=>a.kind==="task"&&a.detail==="Priority: urgent").length;
 return {items:limited,overdue,review,urgent,partial};
}
export function renderDailyFocus(actions=[],partial=false){
 const model=dailyFocusModel(actions,partial);
 const list=model.items.length?model.items.map((a,index)=>'<li><span class="focus-number">'+(index+1)+'</span><span><b>'+escapeText(a.title)+'</b><small>'+escapeText(a.detail)+'</small></span><a href="'+safeDestination(a)+'">Open →</a></li>').join(""):
 '<li><span><b>No pressing priorities in this view</b><small>Choose a starting action below to keep your sales work moving.</small></span></li>';
 const signal=[
  model.overdue?model.overdue+" overdue task"+(model.overdue===1?"":"s"):"No overdue tasks in the displayed priorities",
  model.review?model.review+" document"+(model.review===1?"":"s")+" awaiting review":"No documents awaiting review in the displayed priorities"
 ].join(" · ");
 return '<section id="daily-focus" class="panel daily-focus" aria-labelledby="daily-focus-heading" tabindex="-1"><p class="focus-eyebrow">GITHUA · DAILY FOCUS</p><h2 id="daily-focus-heading">Start with these three</h2><p class="focus-intro">A short, read-only focus list from your highest-ranked visible recommendations. Choose an action to review; nothing is completed automatically.</p><p class="focus-signal">'+escapeText(signal)+'</p><ol class="focus-items">'+list+'</ol>'+(model.partial?'<p role="status">Some workspace records are unavailable. This focus view may be incomplete.</p>':'')+'<p class="focus-footnote">Counts are based only on the first eight suggested actions, not your entire workspace. Refresh the page to check again.</p></section>';
}
