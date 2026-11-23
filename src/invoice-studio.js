import {calculateInvoice} from "./invoicing-domain.js";
// C1.2a staging-only preview prototype. No persistence, issuance, PDF engine, sending or AI calls.
const esc=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
export function parseMoney(value){
 if(typeof value!=="string"||!/^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,2})?$/.test(value))throw new TypeError("Enter a valid amount with up to two decimal places");
 const [whole,fraction=""]=value.split(".");
 return Number(whole)*100+Number(fraction.padEnd(2,"0"));
}
export function parseTaxPercent(value){
 if(typeof value!=="string"||!/^(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,2})?$/.test(value))throw new TypeError("Enter a tax percentage between 0 and 100");
 const [whole,fraction=""]=value.split(".");
 const basis=Number(whole)*100+Number(fraction.padEnd(2,"0"));
 if(basis>10000)throw new RangeError("Tax percentage must not exceed 100");
 return basis;
}
export function invoicePreviewModel(input){
 const business=String(input.business??"").trim(),customer=String(input.customer??"").trim();
 if(!business||business.length>150||!customer||customer.length>150)throw new TypeError("Business and customer names are required (up to 150 characters)");
 const code=String(input.currency??"KES");
 if(!["KES","EUR","USD","GBP"].includes(code))throw new TypeError("Select a supported currency");
 const items=[];
 for(let i=1;i<=3;i++){
  const description=String(input["description"+i]??"").trim();
  const rawPrice=String(input["price"+i]??"").trim();
  const rawQuantity=String(input["quantity"+i]??"").trim();
  if(!description&&!rawPrice&&!rawQuantity)continue;
  if(!description||!rawPrice||!rawQuantity)throw new TypeError("Complete all fields for item "+i);
  if(description.length>300)throw new TypeError("Item description is too long");
  if(!/^[1-9][0-9]{0,3}$/.test(rawQuantity))throw new TypeError("Quantity for item "+i+" must be a whole number between 1 and 9999");
  items.push({description,quantity:Number(rawQuantity),unitPriceMinor:parseMoney(rawPrice)});
 }
 const taxRateBasisPoints=parseTaxPercent(String(input.taxPercent??"0").trim());
 const discountMinor=parseMoney(String(input.discount??"0").trim());
 const invoice=calculateInvoice({currency:code,items,discountMinor,taxRateBasisPoints});
 return {business,customer,invoice};
}
const format=(n,code)=>code+" "+(n/100).toLocaleString("en-GB",{minimumFractionDigits:2,maximumFractionDigits:2});
export function renderInvoiceStudio({input={},preview=null,error="",csrfToken=""}={}){
 const val=(key,defaultValue="")=>esc(input[key]??defaultValue);
 const rows=[1,2,3].map(i=>'<div class="line"><label>Item '+i+' description<input name="description'+i+'" maxlength="300" value="'+val("description"+i)+'" placeholder="Service or product"></label><label>Qty<input name="quantity'+i+'" inputmode="numeric" value="'+val("quantity"+i,i===1?"1":"")+'" placeholder="1"></label><label>Unit price<input name="price'+i+'" inputmode="decimal" value="'+val("price"+i)+'" placeholder="0.00"></label></div>').join("");
 let previewHtml="";
 if(preview){
  const {business,customer,invoice}=preview;
  const lines=invoice.lines.map(item=>'<tr><td>'+esc(item.description)+'</td><td>'+item.quantity+'</td><td>'+format(item.unitPriceMinor,invoice.currency)+'</td><td>'+format(item.lineTotalMinor,invoice.currency)+'</td></tr>').join("");
  previewHtml='<section class="sheet" aria-label="Invoice draft preview"><p class="kicker">DRAFT PREVIEW · NOT ISSUED</p><h2>Invoice preview</h2><div class="heads"><p><b>From</b><br>'+esc(business)+'</p><p><b>Bill to</b><br>'+esc(customer)+'</p></div><table><thead><tr><th>Description</th><th>Qty</th><th>Unit</th><th>Total</th></tr></thead><tbody>'+lines+'</tbody></table><div class="totals"><p>Subtotal <strong>'+format(invoice.subtotalMinor,invoice.currency)+'</strong></p><p>Discount <strong>−'+format(invoice.discountMinor,invoice.currency)+'</strong></p><p>Tax ('+(invoice.taxRateBasisPoints/100)+'% exclusive) <strong>'+format(invoice.taxMinor,invoice.currency)+'</strong></p><p class="grand">Draft total <strong>'+format(invoice.totalMinor,invoice.currency)+'</strong></p></div><p class="warning">Preview only. No invoice number, tax certification, approval, payment confirmation or delivery has occurred. Review all amounts and tax rules before issuing a compliant invoice.</p></section>';
 }
 const curr=val("currency","KES");
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invoice Studio Preview · Githua Sales Assistant</title><style>'+
 '*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 95% 0,#3c2548,#120d1c 60%);color:#f8edf9;font:15px/1.5 system-ui,sans-serif}main{max-width:1050px;margin:auto;padding:28px 18px 70px}h1{font:40px Georgia,serif;margin:16px 0 7px}h2{font:30px Georgia,serif;margin:0 0 14px}.muted{color:#ddc8e5}.nav{display:flex;gap:17px;flex-wrap:wrap}a{color:#f7d8fd}form,.sheet{background:linear-gradient(130deg,#35213c,#211529);padding:25px;border:1px solid #a186ac;border-radius:20px;margin:22px 0}label{display:grid;gap:5px;font-weight:650}input,select{width:100%;background:#180f1d;border:1px solid #a18caa;color:#fff;border-radius:9px;padding:12px;font:inherit}.fields,.line{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}.line{grid-template-columns:2fr .65fr 1fr}.button{background:linear-gradient(100deg,#ffe2c4,#d4a2f7);border:0;border-radius:30px;padding:13px 23px;font-weight:800;color:#261727;cursor:pointer}.note{color:#e8d2ee;font-size:13px}.error{padding:15px;border:1px solid #ffbdc5;border-radius:10px;color:#ffe1df}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 8px;border-bottom:1px solid #9b859d}th:last-child,td:last-child{text-align:right}.heads{display:flex;justify-content:space-between;gap:30px}.totals{max-width:360px;margin:25px 0 25px auto}.totals p{display:flex;justify-content:space-between;gap:12px}.grand{font-size:21px;border-top:1px solid #a18caa;padding-top:14px}.kicker{letter-spacing:.14em;font-weight:700;color:#ffddb8;font-size:12px}.warning{padding:13px;border:1px dashed #bc9cbd;font-size:13px}.sheet{background:#fff;color:#241527}.sheet .warning{color:#46364c}.sheet .kicker{color:#693666}.sheet th,.sheet td{border-color:#ded5e1}@media(max-width:700px){.fields,.line{grid-template-columns:1fr}.heads{display:block}h1{font-size:32px}}@media print{body{background:#fff;color:#111}header,form,.screen-only{display:none!important}main{max-width:none;padding:0}.sheet{margin:0;border:0;box-shadow:none;border-radius:0;padding:0}a{display:none}}'+
 '</style></head><body><main><header><nav class="nav"><a href="/">← Dashboard</a><a href="/documents">Documents</a><a href="/next-actions">Next Actions</a></nav><h1>Invoice Studio</h1><p class="muted">Create a clear invoice preview without accounting expertise. This is an offline-style preview: nothing is saved or sent.</p></header>'+
 '<form method="post" action="/invoice-studio" autocomplete="off"><input type="hidden" name="csrf" value="'+esc(csrfToken)+'"><h2>Invoice details</h2><div class="fields"><label>Business name<input required maxlength="150" name="business" value="'+val("business")+'" placeholder="Your registered business"></label><label>Customer name<input required maxlength="150" name="customer" value="'+val("customer")+'" placeholder="Customer name"></label><label>Currency<select name="currency">'+["KES","EUR","USD","GBP"].map(c=>'<option value="'+c+'"'+(curr===c?" selected":"")+'>'+c+'</option>').join("")+'</select></label></div><h3>Products or services</h3>'+rows+'<div class="fields"><label>Discount ('+esc(curr)+')<input name="discount" inputmode="decimal" value="'+val("discount","0")+'"></label><label>Tax percentage (0 if none)<input name="taxPercent" inputmode="decimal" value="'+val("taxPercent","0")+'"></label></div><p class="note">Tax is entered manually and calculated on a tax-exclusive basis. Do not assume this preview meets local VAT, eTIMS or other fiscal invoicing rules. Currency amounts support two decimal places in this prototype.</p><button class="button" type="submit">Calculate and preview invoice</button></form>'+
 (error?'<p class="error" role="alert">'+esc(error)+'</p>':"")+previewHtml+(preview?'<p class="screen-only">To save a PDF of this unissued preview, use your browser’s Print command, then select Save as PDF. This is not a finalized tax invoice.</p>':"")+'</main></body></html>';
}
