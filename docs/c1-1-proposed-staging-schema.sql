-- C1.1 OFFLINE DRAFT ONLY. DO NOT MOVE INTO migrations/ or apply without
-- explicit staging migration approval and validation against actual D1 state.
-- Additive tables separate from the existing business_documents workflow.
-- SQLite/D1: PRAGMA foreign_keys=ON is required during all writes.
CREATE TABLE IF NOT EXISTS c1_customers (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 display_name TEXT NOT NULL CHECK(length(trim(display_name)) BETWEEN 1 AND 200),
 email TEXT,
 phone TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(organization_id,id)
);
CREATE INDEX IF NOT EXISTS idx_c1_customers_org ON c1_customers(organization_id,updated_at DESC);

CREATE TABLE IF NOT EXISTS c1_invoice_sequences (
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 series TEXT NOT NULL CHECK(length(series) BETWEEN 1 AND 24),
 last_number INTEGER NOT NULL DEFAULT 0 CHECK(last_number>=0),
 PRIMARY KEY(organization_id,series)
);
CREATE TABLE IF NOT EXISTS c1_invoices (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 customer_id TEXT,
 currency TEXT NOT NULL CHECK(length(currency)=3 AND currency=upper(currency)),
 reference TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('draft','ready_for_review','issued','voided')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1),
 issue_date TEXT,
 due_date TEXT,
 source_business_document_id TEXT,
 customer_snapshot_json TEXT NOT NULL,
 business_snapshot_json TEXT NOT NULL,
 line_items_json TEXT NOT NULL,
 tax_mode TEXT NOT NULL CHECK(tax_mode IN ('exclusive','inclusive','exempt','none')),
 tax_rate_basis_points INTEGER NOT NULL CHECK(tax_rate_basis_points BETWEEN 0 AND 10000),
 subtotal_minor INTEGER NOT NULL CHECK(subtotal_minor BETWEEN 0 AND 9000000000000),
 discount_minor INTEGER NOT NULL CHECK(discount_minor>=0 AND discount_minor<=subtotal_minor),
 tax_minor INTEGER NOT NULL CHECK(tax_minor BETWEEN 0 AND 9000000000000),
 total_minor INTEGER NOT NULL CHECK(total_minor BETWEEN 0 AND 9000000000000),
 created_by TEXT NOT NULL REFERENCES users(id),
 issued_by TEXT REFERENCES users(id),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(organization_id,id),
 UNIQUE(organization_id,reference),
 FOREIGN KEY(organization_id,customer_id) REFERENCES c1_customers(organization_id,id),
 -- Source document tenant ownership must be checked in authorized service code;
 -- business_documents does not currently expose a composite tenant+id unique key.
 CHECK((status IN ('issued','voided') AND issue_date IS NOT NULL AND issued_by IS NOT NULL) OR status IN ('draft','ready_for_review'))
);
CREATE INDEX IF NOT EXISTS idx_c1_invoices_org_status ON c1_invoices(organization_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_c1_invoices_customer ON c1_invoices(organization_id,customer_id);

CREATE TABLE IF NOT EXISTS c1_payments (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 invoice_id TEXT NOT NULL,
 currency TEXT NOT NULL CHECK(length(currency)=3 AND currency=upper(currency)),
 amount_minor INTEGER NOT NULL CHECK(amount_minor BETWEEN 1 AND 9000000000000),
 status TEXT NOT NULL CHECK(status IN ('pending','verified','reversed')),
 method TEXT NOT NULL CHECK(method IN ('bank_transfer','mobile_money','cash','card_provider','other')),
 provider_name TEXT,
 provider_reference TEXT,
 recorded_by TEXT NOT NULL REFERENCES users(id),
 verified_by TEXT REFERENCES users(id),
 recorded_at TEXT NOT NULL,
 verified_at TEXT,
 reversal_reason TEXT,
 updated_at TEXT NOT NULL,
 UNIQUE(organization_id,id),
 FOREIGN KEY(organization_id,invoice_id) REFERENCES c1_invoices(organization_id,id),
 CHECK((status='verified' AND verified_by IS NOT NULL AND verified_at IS NOT NULL) OR status!='verified')
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_c1_payment_provider_reference ON c1_payments(organization_id,provider_name,provider_reference)
 WHERE provider_name IS NOT NULL AND provider_reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_c1_payments_invoice ON c1_payments(organization_id,invoice_id,recorded_at DESC);

CREATE TABLE IF NOT EXISTS c1_receipts (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 payment_id TEXT NOT NULL,
 invoice_id TEXT NOT NULL,
 reference TEXT NOT NULL,
 currency TEXT NOT NULL CHECK(length(currency)=3 AND currency=upper(currency)),
 amount_minor INTEGER NOT NULL CHECK(amount_minor BETWEEN 1 AND 9000000000000),
 snapshot_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','issued','voided')),
 prepared_by TEXT NOT NULL REFERENCES users(id),
 issued_by TEXT REFERENCES users(id),
 issued_at TEXT,
 created_at TEXT NOT NULL,
 UNIQUE(organization_id,id),
 UNIQUE(organization_id,reference),
 UNIQUE(organization_id,payment_id),
 FOREIGN KEY(organization_id,payment_id) REFERENCES c1_payments(organization_id,id),
 FOREIGN KEY(organization_id,invoice_id) REFERENCES c1_invoices(organization_id,id),
 CHECK((status IN ('issued','voided') AND issued_at IS NOT NULL AND issued_by IS NOT NULL) OR status='draft')
);
CREATE INDEX IF NOT EXISTS idx_c1_receipts_invoice ON c1_receipts(organization_id,invoice_id,created_at DESC);

CREATE TABLE IF NOT EXISTS c1_financial_audit (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 actor_user_id TEXT NOT NULL REFERENCES users(id),
 resource_kind TEXT NOT NULL CHECK(resource_kind IN ('invoice','payment','receipt')),
 resource_id TEXT NOT NULL,
 event_type TEXT NOT NULL,
 event_json TEXT NOT NULL,
 occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_c1_audit_org_created ON c1_financial_audit(organization_id,occurred_at DESC);
