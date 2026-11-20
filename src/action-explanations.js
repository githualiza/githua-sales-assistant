// Phase B4: deterministic explanations; no AI inference, state changes or external calls.
const cleanId=id=>typeof id==="string"&&/^[a-zA-Z0-9_-]{1,100}$/.test(id)?id:null;
export function actionExplanation(action){
 const kind=action?.kind;
 if(kind==="task"){
  const overdue=action.detail==="Past due — check your deadline";
  const soon=action.detail==="Due within 48 hours";
  const urgent=action.detail==="Priority: urgent";
  const high=action.detail==="Priority: high";
  const reason=overdue?"The saved due date is already past.":soon?"The saved due date is within the next 48 hours.":urgent?"The task is marked urgent in your workspace.":high?"The task is marked high priority in your workspace.":"This task is still open or in progress.";
  return {reason,next:"Open the task, check its due date and progress, and decide the next step.",href:cleanId(action.id)?"/tasks/"+encodeURIComponent(action.id):"/tasks",link:"Review task"};
 }
 if(kind==="document"){
  if(action.detail==="Waiting for authorized document review")return {reason:"The document is marked ready for review.",next:"An authorized reviewer can check the document and its review history.",href:"/documents",link:"Review document"};
  if(action.detail==="Rejected — review feedback and revise")return {reason:"The document was rejected during review.",next:"Check review feedback before preparing a revised draft.",href:"/documents",link:"Review feedback"};
 }
 if(kind==="lead")return {reason:"This lead is currently marked new.",next:"Open the lead, verify its details and decide whether to follow up. No message will be sent automatically.",href:cleanId(action.id)?"/leads/"+encodeURIComponent(action.id):"/leads",link:"Review lead"};
 return {reason:"This item appears in your active workspace.",next:"Review its current status before taking action.",href:"/next-actions",link:"View actions"};
}
