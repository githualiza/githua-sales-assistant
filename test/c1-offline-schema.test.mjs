import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync,readdirSync} from "node:fs";
const sql=readFileSync(new URL("../docs/c1-1-proposed-staging-schema.sql",import.meta.url),"utf8");
const plan=readFileSync(new URL("../docs/c1-1-security-and-staging-gates.md",import.meta.url),"utf8");
const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
test("C1.1 is a documented proposal, not an executable migration",()=>{
 assert.match(sql,/OFFLINE DRAFT ONLY/);
 assert.match(plan,/disposable local D1\/SQLite/);
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
 assert.ok(!readdirSync(new URL("../migrations/",import.meta.url)).some(n=>n.startsWith("20261120_c1")));
});
test("new financial tables are clearly tenant keyed",()=>{
 for(const table of ["c1_customers","c1_invoice_sequences","c1_invoices","c1_payments","c1_receipts","c1_financial_audit"]){
  const start=sql.indexOf("CREATE TABLE IF NOT EXISTS "+table+" (");
  assert.ok(start>=0,table);
  const chunk=sql.slice(start,sql.indexOf(");",start)+2);
  assert.match(chunk,/organization_id TEXT NOT NULL/,table);
 }
});
test("receipt and payment schema reject duplicates and invalid states by design",()=>{
 assert.match(sql,/UNIQUE\(organization_id,payment_id\)/);
 assert.match(sql,/CREATE UNIQUE INDEX IF NOT EXISTS ux_c1_payment_provider_reference/);
 assert.match(sql,/CHECK\(status IN \('pending','verified','reversed'\)\)/);
 assert.match(sql,/amount_minor INTEGER NOT NULL CHECK\(amount_minor BETWEEN 1 AND 9000000000000\)/);
 assert.match(sql,/FOREIGN KEY\(organization_id,invoice_id\) REFERENCES c1_invoices\(organization_id,id\)/);
});
test("nontrivial business invariants are explicitly deferred to audited service logic",()=>{
 assert.match(plan,/constraints alone do \*\*not\*\* enforce all of this/);
 assert.match(plan,/atomic authorization boundary/);
 assert.match(plan,/legacy.*business_documents/);
 assert.match(plan,/separately gated/);
});
