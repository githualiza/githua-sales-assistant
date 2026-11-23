#!/usr/bin/env python3
"""Offline-only integration checks against the actual ordered repository migration schemas.
Never opens or connects to Cloudflare, staging, production, or an external DB.
"""
import sqlite3
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MIGRATIONS=ROOT/"migrations"
PROPOSAL=ROOT/"docs"/"c1-1-proposed-staging-schema.sql"
def reject_integrity(con, statement, values=()):
    try:
        con.execute(statement, values)
    except sqlite3.IntegrityError:
        return
    raise AssertionError("Expected integrity constraint to reject: "+statement[:100])

def main():
    # Reproduce ordered baseline migrations first, then the proposed *non-migration* schema.
    with tempfile.TemporaryDirectory(prefix="githua-c1-offline-") as folder:
        path=Path(folder)/"disposable.sqlite"
        con=sqlite3.connect(str(path))
        con.execute("PRAGMA foreign_keys=ON")
        assert con.execute("PRAGMA foreign_keys").fetchone()[0]==1
        for sql in sorted(MIGRATIONS.glob("*.sql")):
            con.executescript(sql.read_text(encoding="utf-8"))
            assert not con.execute("PRAGMA foreign_key_check").fetchall(), sql.name
        con.executescript(PROPOSAL.read_text(encoding="utf-8"))
        assert not con.execute("PRAGMA foreign_key_check").fetchall()
        for org in ("orgA","orgB"):
            con.execute("INSERT INTO organizations(id,slug,name) VALUES(?,?,?)",(org,org,org))
        con.execute("INSERT INTO users(id,identity_subject) VALUES('userA','subjectA')")
        con.execute("INSERT INTO users(id,identity_subject) VALUES('userB','subjectB')")
        stamp="2026-11-23T10:00:00Z"
        con.execute("INSERT INTO c1_customers(id,organization_id,display_name,created_at,updated_at) VALUES(?,?,?,?,?)",("custA","orgA","Customer A",stamp,stamp))
        con.execute("INSERT INTO c1_customers(id,organization_id,display_name,created_at,updated_at) VALUES(?,?,?,?,?)",("custB","orgB","Customer B",stamp,stamp))
        invoice="INSERT INTO c1_invoices(id,organization_id,customer_id,currency,reference,status,customer_snapshot_json,business_snapshot_json,line_items_json,tax_mode,tax_rate_basis_points,subtotal_minor,discount_minor,tax_minor,total_minor,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        def inv(id,org,customer,ref,total=2000):
            return (id,org,customer,"KES",ref,"draft","{}","{}","[]","exclusive",0,total,0,0,total,"userA",stamp,stamp)
        con.execute(invoice,inv("invA","orgA","custA","A-001"))
        con.execute(invoice,inv("invA2","orgA","custA","A-002"))
        con.execute(invoice,inv("invB","orgB","custB","B-001"))
        reject_integrity(con,invoice,inv("bad-cross-customer","orgA","custB","bad-001"))
        reject_integrity(con,invoice,inv("bad-reference","orgA","custA","A-001"))
        reject_integrity(con,invoice,inv("bad-negative","orgA","custA","A-003",-1))
        payment="INSERT INTO c1_payments(id,organization_id,invoice_id,currency,amount_minor,status,method,provider_name,provider_reference,recorded_by,verified_by,recorded_at,verified_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        def pay(id,org,invoice,provider_ref,amount=1000,status="verified"):
            return (id,org,invoice,"KES",amount,status,"mobile_money","mpesa",provider_ref,"userA","userA" if status=="verified" else None,stamp,stamp if status=="verified" else None,stamp)
        con.execute(payment,pay("payA","orgA","invA","transactionA"))
        con.execute(payment,pay("payB","orgB","invB","transactionB"))
        con.execute(payment,pay("payA2","orgA","invA2","transactionA2"))
        reject_integrity(con,payment,pay("cross-pay","orgB","invA","wrongtenant"))
        reject_integrity(con,payment,pay("duplicate-provider","orgA","invA","transactionA"))
        reject_integrity(con,payment,pay("negative-payment","orgA","invA","negative",-1))
        bad_verified=list(pay("bad-no-verifier","orgA","invA","bad-no-verifier"))
        bad_verified[10]=None
        reject_integrity(con,payment,tuple(bad_verified))
        bad_verified[10]="userA"
        bad_verified[12]=None
        reject_integrity(con,payment,tuple(bad_verified))
        receipt="INSERT INTO c1_receipts(id,organization_id,payment_id,invoice_id,reference,currency,amount_minor,snapshot_json,status,prepared_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
        def rec(id,org,payment,invoice,reference):
            return (id,org,payment,invoice,reference,"KES",1000,"{}","draft","userA",stamp)
        con.execute(receipt,rec("recA","orgA","payA","invA","R-001"))
        reject_integrity(con,receipt,rec("bad-wrong-invoice","orgA","payA2","invA","R-002"))
        reject_integrity(con,receipt,rec("bad-cross-tenant","orgB","payA","invB","R-003"))
        reject_integrity(con,receipt,rec("bad-duplicate-payment","orgA","payA","invA","R-004"))
        reject_integrity(con,receipt,rec("bad-duplicate-reference","orgA","payA2","invA2","R-001"))
        assert not con.execute("PRAGMA foreign_key_check").fetchall()
        con.rollback()
        con.close()
    print("PASS: full ordered legacy schema + offline C1 schema; tenant boundaries, amounts, duplicate payment/receipt, correct invoice-payment composite FK.")

if __name__=="__main__":
    main()
