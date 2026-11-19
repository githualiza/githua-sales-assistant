// SQL shared by the Worker and SQLite runtime regression tests.
// The transition_id is unique per attempt; the audit insert can only match a committed transition.
export const deliveryPreparationUpdateSQL = `UPDATE business_document_delivery_preparations SET recipient_email=?,subject=?,message=?
WHERE id=? AND organization_id=? AND status='prepared'
AND EXISTS (SELECT 1 FROM business_documents d WHERE d.id=business_document_delivery_preparations.document_id AND d.organization_id=? AND d.status='approved')
AND NOT EXISTS (SELECT 1 FROM business_document_delivery_approvals a
WHERE a.preparation_id=business_document_delivery_preparations.id
AND a.organization_id=business_document_delivery_preparations.organization_id
AND a.status IN ('pending_approval','approved'))
RETURNING id,status`;

const matchingContent = `EXISTS (
 SELECT 1 FROM business_document_delivery_preparations p
 JOIN business_documents d ON d.id=p.document_id AND d.organization_id=p.organization_id
 WHERE p.id=? AND p.organization_id=? AND p.document_id=business_document_delivery_approvals.document_id
 AND p.status='prepared' AND d.status='approved'
 AND p.recipient_email=? AND p.subject=? AND p.message=? AND d.updated_at=?
)`;

export const approvalUpdateSQL = `UPDATE business_document_delivery_approvals
SET status=?,revision=?,approved_fingerprint=?,actor_id=?,decision_reason=?,updated_at=?,transition_id=?
WHERE preparation_id=? AND organization_id=? AND revision=? AND status=?
AND ${matchingContent}`;

export const approvalInsertSQL = `INSERT INTO business_document_delivery_approvals
(preparation_id,organization_id,document_id,status,revision,approved_fingerprint,actor_id,decision_reason,updated_at,transition_id)
SELECT ?,?,?,?,?,?,?,?,?,?
WHERE EXISTS (
 SELECT 1 FROM business_document_delivery_preparations p
 JOIN business_documents d ON d.id=p.document_id AND d.organization_id=p.organization_id
 WHERE p.id=? AND p.organization_id=? AND p.document_id=? AND p.status='prepared' AND d.status='approved'
 AND p.recipient_email=? AND p.subject=? AND p.message=? AND d.updated_at=?
) AND NOT EXISTS (
 SELECT 1 FROM business_document_delivery_approvals a WHERE a.preparation_id=? AND a.organization_id=?
)`;

export const approvalAuditSQL = `INSERT INTO business_document_delivery_audit
(id,organization_id,preparation_id,actor_id,actor_role,action,previous_status,new_status,revision,reason,created_at)
SELECT ?,?,?,?,?,?,?,?,?,?,?
WHERE EXISTS (SELECT 1 FROM business_document_delivery_approvals a
WHERE a.preparation_id=? AND a.organization_id=? AND a.revision=? AND a.transition_id=?)`;
