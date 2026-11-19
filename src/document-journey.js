// Small, accessible workflow orientation, only rendered on the isolated staging Worker.
// No scripts, writes, API calls, role elevation, or delivery capability.
export function isStagingJourney(request, env) {
 return env.STAGING_ENVIRONMENT === "true" &&
   new URL(request.url).hostname === "githua-sales-assistant-staging.githualiza.workers.dev";
}
export function workflowGuide(stage) {
 const stages={
  assistant:["1. Create & save","Choose a guided document, fill in the details and select Save draft. Then use Review saved documents to continue.","/documents","Review saved documents"],
  documents:["2. Review & approve","Open your saved draft, then Submit for review. Authorized reviewers can approve the document. Once approved, Prepare email saves delivery details only.","/deliveries","Open Delivery Review"],
  deliveries:["3. Review delivery","Request internal delivery approval, review the prepared content and approve, reject or revoke according to permissions. No emails are sent.","/documents","Back to Documents"]
 };
 const item=stages[stage];if(!item)throw Error("Unknown workflow stage");
 return `<section class="journey-steps" aria-label="Document workflow"><style>
 .journey-steps{margin:14px 0 22px;padding:16px 20px;border:1px solid rgba(237,202,247,.43);border-radius:15px;background:rgba(29,17,39,.79);color:#f8effc;font:14px/1.5 system-ui,sans-serif}
 .journey-steps .journey-label{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#e8c5ff}
 .journey-steps strong{display:block;font-size:17px;margin:5px 0;color:#fff5e9}
 .journey-steps p{margin:5px 0 10px;color:#f0e1f5}
 .journey-steps a{color:#ffe1c4;text-decoration:underline;text-underline-offset:3px}
 .journey-steps details{margin-top:10px;padding-top:8px;border-top:1px solid rgba(255,255,255,.18)}
 .journey-steps summary{cursor:pointer;color:#f3daff;font-weight:650}
 .journey-steps a:focus-visible,.journey-steps summary:focus-visible{outline:2px solid #ffe1c4;outline-offset:4px}
 </style><div class="journey-label">Your document journey · Create → Review → Prepare</div>
 <strong>${item[0]}</strong><p>${item[1]}</p><a href="${item[2]}">${item[3]} →</a>
 <details><summary>Show me how</summary><p>Document review and delivery approval are separate steps. Your progress stays saved in the workspace; only permitted roles can approve. Preparing a delivery does not send an email.</p></details></section>`;
}
