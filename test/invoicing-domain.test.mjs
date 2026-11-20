import test from "node:test";
import assert from "node:assert/strict";
import {calculateInvoice,reconcilePayments,receiptEligibility,DELIVERY_DEFAULTS} from "../src/invoicing-domain.js";
import {readFileSync} from "node:fs";
const params={currency:"KES",items:[{description:"Consulting",quantity:3,unitPriceMinor:125000},{description:"Support",quantity:1,unitPriceMinor:50000}],discountMinor:25000,taxRateBasisPoints:1600};
test("invoice totals are integer minor units with aggregate half-up tax",()=>{
 const x=calculateInvoice(params);
 assert.deepEqual([x.subtotalMinor,x.discountMinor,x.taxableMinor,x.taxMinor,x.totalMinor],[425000,25000,400000,64000,464000]);
 assert.equal(x.taxMode,"exclusive");
 assert.equal(calculateInvoice({currency:"USD",items:[{description:"Tiny",quantity:1,unitPriceMinor:1}],taxRateBasisPoints:5000}).taxMinor,1);
});
test("invoice rejects invalid, huge, ambiguous money or taxes",()=>{
 for(const x of [
  {...params,currency:"KES/UGX"}, {...params,discountMinor:99999999},
  {...params,discountMinor:1.5}, {...params,taxRateBasisPoints:10001},
  {...params,items:[]}, {...params,items:[{description:"",quantity:1,unitPriceMinor:200}]},
  {...params,items:[{description:"Overflow",quantity:10000,unitPriceMinor:9_000_000_000_000}]},
  {...params,items:[{description:"Bad",quantity:0,unitPriceMinor:10}]},
  {...params,items:[{description:"Bad",quantity:1,unitPriceMinor:-1}]}
 ])assert.throws(()=>calculateInvoice(x));
});
test("partial and full payments use VERIFIED entries only",()=>{
 const x=reconcilePayments({currency:"KES",invoiceTotalMinor:10000,payments:[
  {id:"pending",currency:"KES",amountMinor:6000,status:"pending"},
  {id:"paid",currency:"KES",amountMinor:3000,status:"verified"},
  {id:"reversed",currency:"KES",amountMinor:1000,status:"reversed"}
 ]});
 assert.equal(x.status,"partially_paid");assert.equal(x.paidMinor,3000);assert.equal(x.balanceMinor,7000);
 assert.equal(reconcilePayments({currency:"KES",invoiceTotalMinor:3000,payments:[{id:"p",currency:"KES",amountMinor:3000,status:"verified"}]}).status,"paid");
 assert.equal(reconcilePayments({currency:"KES",invoiceTotalMinor:1000}).status,"unpaid");
});
test("payments reject duplicates, currency mismatch, overpayment, invalid statuses",()=>{
 const base={currency:"KES",invoiceTotalMinor:1000};
 for(const payments of [
  [{id:"x",currency:"KES",amountMinor:600,status:"verified"},{id:"x",currency:"KES",amountMinor:400,status:"verified"}],
  [{id:"p",currency:"USD",amountMinor:100,status:"verified"}],
  [{id:"p",currency:"KES",amountMinor:1001,status:"verified"}],
  [{id:"p",currency:"KES",amountMinor:100,status:"unconfirmed"}],
  [{id:"p",currency:"KES",amountMinor:0,status:"verified"}]
 ])assert.throws(()=>reconcilePayments({...base,payments}));
});
test("receipt must belong to the same tenant and exact invoice, with verified payment",()=>{
 const invoice={id:"i1",organizationId:"org1",currency:"KES"};
 const p={invoiceId:"i1",organizationId:"org1",currency:"KES",status:"verified",amountMinor:100};
 assert.equal(receiptEligibility(invoice,p).allowed,true);
 for(const wrong of [
  {...p,organizationId:"org2"}, {...p,invoiceId:"i2"},
  {...p,currency:"EUR"}, {...p,status:"pending"}, {...p,amountMinor:0}
 ])assert.equal(receiptEligibility(invoice,wrong).allowed,false);
});
test("delivery stays disabled and C1 has no routes or migrations",()=>{
 assert.equal(DELIVERY_DEFAULTS.enabled,false);
 assert.equal(DELIVERY_DEFAULTS.autoSendEnabled,false);
 assert.equal(DELIVERY_DEFAULTS.manualSendEnabled,false);
 assert.equal(DELIVERY_DEFAULTS.emailEnabled,false);
 assert.equal(DELIVERY_DEFAULTS.whatsappEnabled,false);
 assert.equal(DELIVERY_DEFAULTS.requiresExplicitUserApproval,true);
 const src=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
 assert.doesNotMatch(src,/from ["']\.\/invoicing-domain\.js["']/);
 const staging=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(staging,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
