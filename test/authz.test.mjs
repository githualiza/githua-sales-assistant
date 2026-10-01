import assert from "node:assert/strict";
import { can, requireCapability } from "../src/authz.js";

assert.equal(can("owner", "workspace:manage"), true);
assert.equal(can("admin", "workspace:manage"), false);
assert.equal(can("manager", "sales:manage"), true);
assert.equal(can("agent", "members:manage"), false);
assert.equal(can("viewer", "sales:read"), true);
assert.equal(can("viewer", "sales:manage"), false);
assert.equal(can("unknown", "sales:read"), false);

assert.doesNotThrow(() => requireCapability({ role: "agent", status: "active" }, "sales:manage"));
assert.throws(() => requireCapability({ role: "viewer", status: "active" }, "sales:manage"), /Forbidden/);
assert.throws(() => requireCapability({ role: "owner", status: "disabled" }, "workspace:manage"), /Forbidden/);
assert.throws(() => requireCapability(null, "sales:read"), /Forbidden/);

console.log("Authorization policy tests passed.");
