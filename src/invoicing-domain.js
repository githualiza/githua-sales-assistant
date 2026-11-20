// Phase C1 domain foundation. PURE FUNCTIONS ONLY: no storage, HTTP, providers or sending.
// Financial amounts are integer minor units; tax rates are basis points (0..10000).
// These functions are not tax certification or proof of bank/mobile-money settlement.
const MAX_MINOR=9_000_000_000_000;
function integer(value,min,max,label){
 if(typeof value!=="number"||!Number.isSafeInteger(value)||value<min||value>max)throw new TypeError("Invalid "+label);
 return value;
}
function currency(value){
 if(typeof value!=="string"||!/^[A-Z]{3}$/.test(value))throw new TypeError("Invalid currency");
 return value;
}
function amount(value,label){return integer(value,0,MAX_MINOR,label)}
function safeAdd(a,b,label){
 const n=a+b;
 if(!Number.isSafeInteger(n)||n>MAX_MINOR)throw new RangeError(label+" exceeds supported amount");
 return n;
}
export function calculateInvoice({currency:code,items,discountMinor=0,taxRateBasisPoints=0}){
 currency(code);
 if(!Array.isArray(items)||items.length<1||items.length>100)throw new TypeError("Invoice requires 1-100 line items");
 const rate=integer(taxRateBasisPoints,0,10000,"tax rate");
 let subtotalMinor=0;
 const lines=items.map((item,index)=>{
  if(!item||typeof item!=="object")throw new TypeError("Invalid line item");
  if(typeof item.description!=="string"||!item.description.trim()||item.description.length>300)throw new TypeError("Invalid line description");
  const quantity=integer(item.quantity,1,10000,"quantity");
  const unitPriceMinor=amount(item.unitPriceMinor,"unit price");
  const lineTotalMinor=safeAdd(0,quantity*unitPriceMinor,"line total");
  subtotalMinor=safeAdd(subtotalMinor,lineTotalMinor,"subtotal");
  return {index,description:item.description.trim(),quantity,unitPriceMinor,lineTotalMinor};
 });
 const discount=amount(discountMinor,"discount");
 if(discount>subtotalMinor)throw new RangeError("Discount exceeds subtotal");
 const taxableMinor=subtotalMinor-discount;
 // Explicit tax-exclusive model. Round the aggregate tax once, half up.
 const taxMinor=Math.floor((taxableMinor*rate+5000)/10000);
 const totalMinor=safeAdd(taxableMinor,taxMinor,"invoice total");
 return {currency:code,lines,subtotalMinor,discountMinor:discount,taxableMinor,taxRateBasisPoints:rate,taxMinor,totalMinor,taxMode:"exclusive"};
}
export function reconcilePayments({invoiceTotalMinor,currency:code,payments=[]}){
 const due=amount(invoiceTotalMinor,"invoice total");
 currency(code);
 if(!Array.isArray(payments)||payments.length>1000)throw new TypeError("Invalid payments");
 let paidMinor=0;
 const verifiedPayments=[];
 const ids=new Set();
 for(const p of payments){
  if(!p||typeof p!=="object"||typeof p.id!=="string"||!p.id||ids.has(p.id))throw new TypeError("Invalid or duplicate payment ID");
  ids.add(p.id);
  if(p.currency!==code)throw new TypeError("Payment currency mismatch");
  const minor=amount(p.amountMinor,"payment amount");
  if(minor===0)throw new TypeError("Payment must be positive");
  if(!["pending","verified","reversed"].includes(p.status))throw new TypeError("Invalid payment state");
  if(p.status==="verified"){
   paidMinor=safeAdd(paidMinor,minor,"verified payments");
   verifiedPayments.push({id:p.id,amountMinor:minor,currency:code});
  }
 }
 if(paidMinor>due)throw new RangeError("Overpayment requires separate review; no receipt may be issued automatically");
 return {currency:code,invoiceTotalMinor:due,paidMinor,balanceMinor:due-paidMinor,status:paidMinor===0?"unpaid":paidMinor===due?"paid":"partially_paid",verifiedPayments};
}
export function receiptEligibility(invoice,payment){
 if(!invoice||!payment||invoice.organizationId!==payment.organizationId||invoice.id!==payment.invoiceId)return {allowed:false,reason:"Invoice/payment tenant or reference mismatch"};
 if(payment.status!=="verified")return {allowed:false,reason:"Payment has not been verified"};
 if(payment.currency!==invoice.currency)return {allowed:false,reason:"Currency mismatch"};
 try{if(amount(payment.amountMinor,"payment amount")===0)return {allowed:false,reason:"Invalid payment amount"}}catch{return {allowed:false,reason:"Invalid payment amount"}}
 return {allowed:true,reason:"Verified payment eligible for an internal receipt draft only"};
}
export const DELIVERY_DEFAULTS=Object.freeze({
 enabled:false,
 autoSendEnabled:false,
 manualSendEnabled:false,
 emailEnabled:false,
 whatsappEnabled:false,
 requiresExplicitUserApproval:true,
 requireIdempotencyKey:true,
 requireAuditTrail:true
});
