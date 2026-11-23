import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parseMoney,parseTaxPercent,invoicePreviewModel,renderInvoiceStudio} from "../src/invoice-studio.js";
const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
test("decimal amounts and percentage parse exactly without float conversions",()=>{
 assert.equal(parseMoney("1.25"),125);
 assert.equal(parseMoney("100"),10000);
 assert.equal(parseMoney("0.01"),1);
 assert.equal(parseTaxPercent("16"),1600);
 assert.equal(parseTaxPercent("5.25"),525);
 for(const value of ["1.999","1e5","-10","NaN","1,000.00","", "99999999999999"])assert.throws(()=>parseMoney(value));
 for(const value of ["101","16.001","-1","1000"])assert.throws(()=>parseTaxPercent(value));
});
test("simple invoice preview calculates tax-exclusive totals with discount",()=>{
 const p=invoicePreviewModel({business:"Githua AI Systems",customer:"Example Client",currency:"KES",description1:"Consulting",quantity1:"2",price1:"1500.00",discount:"100",taxPercent:"16"});
 assert.equal(p.invoice.subtotalMinor,300000);
 assert.equal(p.invoice.discountMinor,10000);
 assert.equal(p.invoice.taxMinor,46400);
 assert.equal(p.invoice.totalMinor,336400);
 assert.equal(p.invoice.lines.length,1);
});
test("form rejects incomplete items and unsupported currency",()=>{
 const base={business:"Company",customer:"Client",description1:"Consulting",quantity1:"1",price1:"100"};
 for(const change of [{quantity1:""},{price1:""},{business:""},{customer:""},{currency:"JPY"},{taxPercent:"101"},{quantity1:"0"},{discount:"101"}])assert.throws(()=>invoicePreviewModel({...base,...change}));
});
test("HTML escapes all untrusted text and includes clear unissued notices",()=>{
 const html=renderInvoiceStudio({input:{business:'<script>alert(1)</script>',customer:'" autofocus'},csrfToken:'<unsafe>'});
 assert.doesNotMatch(html,/<script>alert\(1\)<\/script>/);
 assert.match(html,/&lt;script&gt;/);
 assert.match(html,/value="&lt;unsafe&gt;"/);
 const preview=renderInvoiceStudio({preview:invoicePreviewModel({business:"Demo",customer:"Client",description1:"Project",quantity1:"1",price1:"99"}),csrfToken:"signed-token"});
 assert.match(preview,/DRAFT PREVIEW · NOT ISSUED/);
 assert.match(preview,/Save as PDF/);
 assert.match(preview,/@media print/);
 assert.doesNotMatch(preview,/Send invoice now|invoice sent successfully/i);
});
test("Invoice Studio is staging gated, session authenticated, role restricted and signed-CSRF-protected",()=>{
 assert.match(source,/async function invoiceStudioPage\(request,env\)/);
 assert.match(source,/if\(!isStagingSetupRequest\(request,env\)\)return json/);
 assert.match(source,/const session=await requireSession\(request,env\)/);
 assert.match(source,/DOCUMENT_WRITE_ROLES\.has\(membership\.role\)/);
 assert.match(source,/origin!==new URL\(request\.url\)\.origin/);
 assert.match(source,/token\.purpose!=="invoice-studio-preview"/);
 assert.match(source,/token\.uid!==session\.uid/);
 assert.match(source,/token\.org!==membership\.organization_id/);
 assert.match(source,/url\.pathname === "\/invoice-studio"\) return await invoiceStudioPage/);
 assert.match(source,/class="invoice-studio-nav" href="\/invoice-studio"/);
 assert.match(source,/Luminous%20Silk%20Ribbons/);
 const cfg=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(cfg,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
