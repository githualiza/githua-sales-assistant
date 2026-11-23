import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {readFileSync} from "node:fs";
test("C1 offline schema validates against complete baseline migrations in disposable SQLite",()=>{
 const res=spawnSync("python3",["scripts/validate-c1-disposable-sqlite.py"],{encoding:"utf8",timeout:20000});
 assert.equal(res.error,undefined,String(res.error||""));
 assert.equal(res.status,0,["C1 SQLite validation failed",res.stdout,res.stderr].join("\n"));
 assert.match(res.stdout,/PASS: full ordered legacy schema/);
});
test("C1 validation cannot access staging or production",()=>{
 const code=readFileSync(new URL("../scripts/validate-c1-disposable-sqlite.py",import.meta.url),"utf8");
 assert.match(code,/tempfile\.TemporaryDirectory/);
 assert.match(code,/sqlite3\.connect/);
 assert.doesNotMatch(code,/cloudflare|requests\.|urllib|wrangler d1 execute/i);
 const config=readFileSync(new URL("../wrangler.staging.jsonc",import.meta.url),"utf8");
 assert.match(config,/"DOCUMENT_DELIVERY_SENDING_ENABLED": "false"/);
});
