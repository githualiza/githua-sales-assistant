export const ROLES = Object.freeze(["owner", "admin", "manager", "agent", "viewer"]);

const ROLE_CAPABILITIES = Object.freeze({
  owner: new Set(["workspace:manage", "members:manage", "sales:manage", "sales:read", "knowledge:manage", "usage:read"]),
  admin: new Set(["members:manage", "sales:manage", "sales:read", "knowledge:manage", "usage:read"]),
  manager: new Set(["sales:manage", "sales:read", "knowledge:manage", "usage:read"]),
  agent: new Set(["sales:manage", "sales:read"]),
  viewer: new Set(["sales:read"]),
});

export function can(role, capability) {
  return ROLE_CAPABILITIES[role]?.has(capability) ?? false;
}

export function requireCapability(membership, capability) {
  if (!membership || membership.status !== "active" || !can(membership.role, capability)) {
    const error = new Error("Forbidden");
    error.status = 403;
    throw error;
  }
}

export async function loadActiveMembership(db, organizationId, userId) {
  if (!db || !organizationId || !userId) return null;
  return db
    .prepare(
      `SELECT id, organization_id, user_id, role, status
       FROM memberships
       WHERE organization_id = ?1 AND user_id = ?2 AND status = 'active'
       LIMIT 1`,
    )
    .bind(organizationId, userId)
    .first();
}

// Tenant IDs are accepted only after an authenticated user has been mapped to
// an active membership. Object-level queries must include organization_id.
export async function authorizeTenant(db, organizationId, userId, capability) {
  const membership = await loadActiveMembership(db, organizationId, userId);
  requireCapability(membership, capability);
  return membership;
}
