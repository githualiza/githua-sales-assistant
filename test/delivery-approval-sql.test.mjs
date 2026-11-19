import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { deliveryPreparationUpdateSQL, approvalInsertSQL, approvalUpdateSQL, approvalAuditSQL } from "../src/delivery-approval-sql.js";

const org="tenant-a", id="prep-1", docId="doc-1", actor="user-1", now="2026-11-19T12:00:00Z", fingerprint="fingerprint-1";
const snapshot=[id,org,"client@example.test","Quote","Prepared message",now];
function dbFixture(){
 const db=new DatabaseSync(":memory:");
 db.exec(`
 CREATE TABLE business_documents(id TEXT PRIMARY KEY,organization_id TEXT,status TEXT,updated_at TEXT);
 CREATE TABLE business_document_delivery_preparations(id TEXT PRIMARY KEY,organization_id TEXT,document_id TEXT,recipient_email TEXT,subject TEXT,message TEXT,status TEXT);
 CREATE TABLE business_document_delivery_approvals(preparation_id TEXT PRIMARY KEY,organization_id TEXT,document_id TEXT,status TEXT,revision INTEGER,approved_fingerprint TEXT,actor_id TEXT,decision_reason TEXT,updated_at TEXT,transition_id TEXT);
 CREATE TABLE business_document_delivery_audit(id TEXT PRIMARY KEY,organization_id TEXT,preparation_id TEXT,actor_id TEXT,actor_role TEXT,action TEXT,previous_status TEXT,new_status TEXT,revision INTEGER,reason TEXT,created_at TEXT);
 INSERT INTO business_documents VALUES ('doc-1','tenant-a','approved','2026-11-19T12:00:00Z');
 INSERT INTO business_document_delivery_preparations VALUES ('prep-1','tenant-a','doc-1','client@example.test','Quote','Prepared message','prepared');
 `);
 return db;
}
function attempt(db, transition, opts={}){
 const {revision=1,prev="prepared",next="pending_approval",insert=true,marker="t-1"}=opts;
 const stmt=insert
 ?db.prepare(approvalInsertSQL)
 :db.prepare(approvalUpdateSQL);
 const args=insert?[id,org,docId,next,revision,fingerprint,actor,"",now,marker,id,org,docId,...snapshot.slice(2),id,org]
 :[next,revision,fingerprint,actor,"",now,marker,id,org,revision-1,prev,...snapshot];
 db.exec("BEGIN IMMEDIATE");
 try{
  const main=stmt.run(...args);
  const audit=db.prepare(approvalAuditSQL).run("audit-"+transition,org,id,actor,"owner",transition,prev,next,revision,"",now,id,org,revision,marker);
  db.exec("COMMIT");
  return {main:main.changes,audit:audit.changes};
 }catch(e){db.exec("ROLLBACK");throw e;}
}
test("initial approval request records exactly one audit event",()=>{
 const db=dbFixture();assert.deepEqual(attempt(db,"request"),{main:1,audit:1});
 assert.equal(db.prepare("SELECT COUNT(*) AS n FROM business_document_delivery_audit").get().n,1);
 db.close();
});
test("racing insert does not generate a phantom audit event",()=>{
 const db=dbFixture();
 assert.deepEqual(attempt(db,"request"),{main:1,audit:1});
 assert.deepEqual(attempt(db,"second-request",{marker:"t-2"}),{main:0,audit:0});
 assert.equal(db.prepare("SELECT COUNT(*) AS n FROM business_document_delivery_audit").get().n,1);db.close();
});
test("stale revision fails without an audit event",()=>{
 const db=dbFixture();attempt(db,"request");
 assert.deepEqual(attempt(db,"approve",{insert:false,prev:"pending_approval",revision:2,marker:"t-2"}),{main:1,audit:1});
 assert.deepEqual(attempt(db,"stale",{insert:false,prev:"pending_approval",revision:2,marker:"t-3"}),{main:0,audit:0});
 assert.equal(db.prepare("SELECT COUNT(*) AS n FROM business_document_delivery_audit").get().n,2);db.close();
});
test("stale content fails and cannot be approved or audited",()=>{
 const db=dbFixture();attempt(db,"request");
 db.prepare("UPDATE business_document_delivery_preparations SET subject='Altered' WHERE id=?").run(id);
 assert.deepEqual(attempt(db,"approve",{insert:false,prev:"pending_approval",revision:2,marker:"t-2"}),{main:0,audit:0});
 assert.equal(db.prepare("SELECT status FROM business_document_delivery_approvals").get().status,"pending_approval");db.close();
});
test("stale document timestamp and unapproved document stop transitions",()=>{
 const db=dbFixture();attempt(db,"request");
 db.prepare("UPDATE business_documents SET updated_at='later' WHERE id=?").run(docId);
 assert.deepEqual(attempt(db,"approve",{insert:false,prev:"pending_approval",revision:2,marker:"t-2"}),{main:0,audit:0});
 db.prepare("UPDATE business_documents SET updated_at=?,status='rejected' WHERE id=?").run(now,docId);
 assert.deepEqual(attempt(db,"approve",{insert:false,prev:"pending_approval",revision:2,marker:"t-3"}),{main:0,audit:0});db.close();
});
test("edit is rejected after an approval request, including stale prechecks",()=>{
 const db=dbFixture();attempt(db,"request");
 const edit=db.prepare(deliveryPreparationUpdateSQL).get("new@example.test","New subject","New message",id,org,org);
 assert.equal(edit,undefined);
 assert.equal(db.prepare("SELECT subject FROM business_document_delivery_preparations").get().subject,"Quote");db.close();
});
test("edit allowed after rejection and not after approval",()=>{
 const db=dbFixture();attempt(db,"request");
 db.prepare("UPDATE business_document_delivery_approvals SET status='rejected' WHERE preparation_id=?").run(id);
 assert.equal(db.prepare(deliveryPreparationUpdateSQL).get("new@example.test","New subject","New message",id,org,org).id,id);
 db.prepare("UPDATE business_document_delivery_approvals SET status='approved' WHERE preparation_id=?").run(id);
 assert.equal(db.prepare(deliveryPreparationUpdateSQL).get("new2@example.test","Next subject","Next message",id,org,org),undefined);db.close();
});
test("audit insert requires matching unique transition token",()=>{
 const db=dbFixture();attempt(db,"request");
 const res=db.prepare(approvalAuditSQL).run("fake",org,id,actor,"owner","approve","pending_approval","approved",1,"",now,id,org,1,"wrong-token");
 assert.equal(res.changes,0);db.close();
});
test("internal approval handler requires owner or admin; no delivery route",()=>{
 const source=readFileSync(new URL("../src/index.js",import.meta.url),"utf8");
 const handler=source.slice(source.indexOf("async function internalDeliveryApproval"),source.indexOf("async function documentManagementPage"));
 assert.match(handler,/\["owner","admin"\]\.includes\(a\.membership\.role\)/);
 assert.match(handler,/env\.DB\.batch\(\[stmt,event\]\)/);
 assert.doesNotMatch(handler,/sendEmail|sendMail|smtp|queue\.send/i);
});
