import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const schema=readFileSync(new URL("../docs/c1-1-proposed-staging-schema.sql",import.meta.url),"utf8");
test("receipt foreign key binds organization, payment, and invoice together",()=>{
 assert.match(schema,/UNIQUE\(organization_id,id,invoice_id\)/);
 assert.match(schema,/FOREIGN KEY\(organization_id,payment_id,invoice_id\) REFERENCES c1_payments\(organization_id,id,invoice_id\)/);
 assert.doesNotMatch(schema,/FOREIGN KEY\(organization_id,payment_id\) REFERENCES c1_payments\(organization_id,id\)/);
});
test("financial table proposal remains offline and delivery-disabled",()=>{
 assert.match(schema,/OFFLINE DRAFT ONLY/);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
