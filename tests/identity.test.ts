/**
 * Tests for the identity system — US-001.
 *
 * Covers:
 * - Identity creation with Ed25519 keypair (human and agent types)
 * - Private key is returned once, never stored
 * - Public key hash uniqueness
 * - Identity listing and retrieval
 * - Org CRUD (create, list, get by name, delete)
 * - Org membership (add, update role, remove, list)
 * - Project CRUD (scoped to org, uniqueness within org)
 * - Project membership (requires org membership, add, update role, remove, list)
 * - Role enforcement (admin, member, readonly)
 * - Identity verification via private key
 * - Cascade deletes (identity -> memberships, org -> projects + memberships)
 * - Error cases (invalid types, duplicate names, missing references)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  IdentityDatabase,
  getDefaultIdentityDbPath,
  type IdentityType,
  type MemberRole,
} from '../src/identity.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ─── Test Helpers ─────────────────────────────────────────────────

let tmpDir: string;
let db: IdentityDatabase;

async function createTestDb(): Promise<IdentityDatabase> {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-identity-'));
  const dbPath = path.join(tmpDir, 'identity.db');
  return await IdentityDatabase.open(dbPath);
}

function cleanupTestDb(): void {
  if (db) {
    try { db.close(); } catch { /* already closed */ }
  }
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

beforeEach(async () => {
  db = await createTestDb();
});

afterEach(() => {
  cleanupTestDb();
});

// ─── Identity CRUD ────────────────────────────────────────────────

describe('Identity — create', () => {
  it('should create a human identity with Ed25519 keypair', async () => {
    const result = await db.createIdentity('alice', 'human');

    expect(result.identity).toBeDefined();
    expect(result.identity.name).toBe('alice');
    expect(result.identity.type).toBe('human');
    expect(result.identity.id).toHaveLength(32); // 16 bytes hex
    expect(result.identity.public_key_hash).toHaveLength(64); // SHA-256 hex
    expect(result.identity.created_at).toBeDefined();

    // Private key returned (Ed25519 secret key = 64 bytes = 88 chars base64)
    expect(result.privateKey).toBeDefined();
    const skBuf = Buffer.from(result.privateKey, 'base64');
    expect(skBuf.length).toBe(64);

    // Public key returned (Ed25519 public key = 32 bytes)
    expect(result.publicKey).toBeDefined();
    const pkBuf = Buffer.from(result.publicKey, 'base64');
    expect(pkBuf.length).toBe(32);
  });

  it('should create an agent identity', async () => {
    const result = await db.createIdentity('ci-bot', 'agent');

    expect(result.identity.name).toBe('ci-bot');
    expect(result.identity.type).toBe('agent');
  });

  it('should generate unique keypairs for each identity', async () => {
    const r1 = await db.createIdentity('alice', 'human');
    const r2 = await db.createIdentity('bob', 'human');

    expect(r1.privateKey).not.toBe(r2.privateKey);
    expect(r1.publicKey).not.toBe(r2.publicKey);
    expect(r1.identity.public_key_hash).not.toBe(r2.identity.public_key_hash);
    expect(r1.identity.id).not.toBe(r2.identity.id);
  });

  it('should trim whitespace from name', async () => {
    const result = await db.createIdentity('  alice  ', 'human');
    expect(result.identity.name).toBe('alice');
  });

  it('should reject empty name', async () => {
    await expect(db.createIdentity('', 'human')).rejects.toThrow('Identity name cannot be empty');
    await expect(db.createIdentity('   ', 'human')).rejects.toThrow('Identity name cannot be empty');
  });

  it('should reject invalid type', async () => {
    await expect(db.createIdentity('alice', 'robot' as IdentityType)).rejects.toThrow(
      "Invalid identity type: 'robot'"
    );
  });
});

describe('Identity — get & list', () => {
  it('should get identity by ID', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const found = db.getIdentity(identity.id);

    expect(found).not.toBeNull();
    expect(found!.name).toBe('alice');
    expect(found!.type).toBe('human');
  });

  it('should get identity by name', async () => {
    await db.createIdentity('alice', 'human');
    const found = db.getIdentityByName('alice');

    expect(found).not.toBeNull();
    expect(found!.name).toBe('alice');
  });

  it('should return null for nonexistent identity', () => {
    expect(db.getIdentity('nonexistent')).toBeNull();
    expect(db.getIdentityByName('nonexistent')).toBeNull();
  });

  it('should list all identities in creation order', async () => {
    await db.createIdentity('alice', 'human');
    await db.createIdentity('bob', 'agent');
    await db.createIdentity('charlie', 'human');

    const identities = db.listIdentities();
    expect(identities).toHaveLength(3);
    expect(identities[0].name).toBe('alice');
    expect(identities[1].name).toBe('bob');
    expect(identities[2].name).toBe('charlie');
  });

  it('should return empty array when no identities exist', () => {
    expect(db.listIdentities()).toHaveLength(0);
  });
});

describe('Identity — delete', () => {
  it('should delete an identity', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    expect(db.deleteIdentity(identity.id)).toBe(true);
    expect(db.getIdentity(identity.id)).toBeNull();
  });

  it('should return false when deleting nonexistent identity', () => {
    expect(db.deleteIdentity('nonexistent')).toBe(false);
  });

  it('should cascade-delete org memberships when identity is deleted', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);

    expect(db.listOrgMembers(org.id)).toHaveLength(1);

    db.deleteIdentity(identity.id);
    expect(db.listOrgMembers(org.id)).toHaveLength(0);
  });

  it('should cascade-delete project memberships when identity is deleted', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);
    const project = await db.createProject(org.id, 'my-project', identity.id);

    expect(db.listProjectMembers(project.id)).toHaveLength(1);

    db.deleteIdentity(identity.id);
    expect(db.listProjectMembers(project.id)).toHaveLength(0);
  });
});

describe('Identity — verify', () => {
  it('should verify an identity with its private key', async () => {
    const result = await db.createIdentity('alice', 'human');

    const verified = await db.verifyIdentity(result.privateKey);
    expect(verified).not.toBeNull();
    expect(verified!.id).toBe(result.identity.id);
    expect(verified!.name).toBe('alice');
  });

  it('should return null for invalid private key', async () => {
    await db.createIdentity('alice', 'human');

    // Random key that doesn't match any identity
    const fakeKey = Buffer.alloc(64);
    expect(await db.verifyIdentity(fakeKey.toString('base64'))).toBeNull();
  });

  it('should return null for malformed private key', async () => {
    expect(await db.verifyIdentity('not-a-valid-key')).toBeNull();
    expect(await db.verifyIdentity('')).toBeNull();
  });
});

// ─── Org CRUD ─────────────────────────────────────────────────────

describe('Org — create', () => {
  it('should create an org', async () => {
    const org = await db.createOrg('acme');
    expect(org.id).toHaveLength(32);
    expect(org.name).toBe('acme');
    expect(org.created_at).toBeDefined();
  });

  it('should create an org and assign founder as admin', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);

    const members = db.listOrgMembers(org.id);
    expect(members).toHaveLength(1);
    expect(members[0].identity_id).toBe(identity.id);
    expect(members[0].role).toBe('admin');
    expect(members[0].name).toBe('alice');
  });

  it('should reject empty org name', async () => {
    await expect(db.createOrg('')).rejects.toThrow('Org name cannot be empty');
  });

  it('should reject duplicate org name', async () => {
    await db.createOrg('acme');
    await expect(db.createOrg('acme')).rejects.toThrow("Org 'acme' already exists");
  });

  it('should reject nonexistent founder identity', async () => {
    await expect(db.createOrg('acme', 'nonexistent')).rejects.toThrow("Identity 'nonexistent' not found");
  });

  it('should trim whitespace from name', async () => {
    const org = await db.createOrg('  acme  ');
    expect(org.name).toBe('acme');
  });
});

describe('Org — get & list', () => {
  it('should get org by ID', async () => {
    const org = await db.createOrg('acme');
    const found = db.getOrg(org.id);
    expect(found).not.toBeNull();
    expect(found!.name).toBe('acme');
  });

  it('should get org by name', async () => {
    await db.createOrg('acme');
    const found = db.getOrgByName('acme');
    expect(found).not.toBeNull();
    expect(found!.name).toBe('acme');
  });

  it('should return null for nonexistent org', () => {
    expect(db.getOrg('nonexistent')).toBeNull();
    expect(db.getOrgByName('nonexistent')).toBeNull();
  });

  it('should list all orgs in creation order', async () => {
    await db.createOrg('acme');
    await db.createOrg('globex');
    await db.createOrg('initech');

    const orgs = db.listOrgs();
    expect(orgs).toHaveLength(3);
    expect(orgs[0].name).toBe('acme');
    expect(orgs[1].name).toBe('globex');
    expect(orgs[2].name).toBe('initech');
  });
});

describe('Org — delete', () => {
  it('should delete an org', async () => {
    const org = await db.createOrg('acme');
    expect(db.deleteOrg(org.id)).toBe(true);
    expect(db.getOrg(org.id)).toBeNull();
  });

  it('should cascade-delete projects when org is deleted', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);
    const project = await db.createProject(org.id, 'my-project', identity.id);

    db.deleteOrg(org.id);
    expect(db.getProject(project.id)).toBeNull();
  });

  it('should cascade-delete org memberships when org is deleted', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);

    db.deleteOrg(org.id);
    expect(db.getOrgMember(org.id, identity.id)).toBeNull();
  });

  it('should return false when deleting nonexistent org', () => {
    expect(db.deleteOrg('nonexistent')).toBe(false);
  });
});

// ─── Org Membership ───────────────────────────────────────────────

describe('Org — membership', () => {
  it('should add a member to an org', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);

    db.addOrgMember(org.id, bob.id, 'member');

    const members = db.listOrgMembers(org.id);
    expect(members).toHaveLength(2);

    const bobMember = members.find(m => m.identity_id === bob.id);
    expect(bobMember).toBeDefined();
    expect(bobMember!.role).toBe('member');
  });

  it('should add a readonly member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: viewer } = await db.createIdentity('viewer', 'agent');
    const org = await db.createOrg('acme', alice.id);

    db.addOrgMember(org.id, viewer.id, 'readonly');

    const role = db.getOrgRole(org.id, viewer.id);
    expect(role).toBe('readonly');
  });

  it('should reject invalid role', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);

    expect(() => db.addOrgMember(org.id, bob.id, 'superadmin' as MemberRole)).toThrow(
      "Invalid role: 'superadmin'"
    );
  });

  it('should reject adding member to nonexistent org', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    expect(() => db.addOrgMember('nonexistent', alice.id, 'member')).toThrow(
      "Org 'nonexistent' not found"
    );
  });

  it('should reject adding nonexistent identity', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id);
    expect(() => db.addOrgMember(org.id, 'nonexistent', 'member')).toThrow(
      "Identity 'nonexistent' not found"
    );
  });

  it('should reject duplicate membership', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id); // alice is already admin

    expect(() => db.addOrgMember(org.id, alice.id, 'member')).toThrow(
      `Identity '${alice.id}' is already a member of org '${org.id}'`
    );
  });

  it('should update member role', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');

    db.updateOrgMemberRole(org.id, bob.id, 'admin');

    const role = db.getOrgRole(org.id, bob.id);
    expect(role).toBe('admin');
  });

  it('should reject updating role for non-member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);

    expect(() => db.updateOrgMemberRole(org.id, bob.id, 'admin')).toThrow(
      `Identity '${bob.id}' is not a member of org '${org.id}'`
    );
  });

  it('should remove a member from an org', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');

    expect(db.removeOrgMember(org.id, bob.id)).toBe(true);
    expect(db.getOrgRole(org.id, bob.id)).toBeNull();
  });

  it('should return false when removing non-member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id);
    expect(db.removeOrgMember(org.id, 'nonexistent')).toBe(false);
  });

  it('should return null role for non-member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);

    expect(db.getOrgRole(org.id, bob.id)).toBeNull();
  });

  it('should list org members with identity details', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bot } = await db.createIdentity('ci-bot', 'agent');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bot.id, 'readonly');

    const members = db.listOrgMembers(org.id);
    expect(members).toHaveLength(2);

    // Members should include name and type
    for (const m of members) {
      expect(m.name).toBeDefined();
      expect(m.type).toBeDefined();
    }
  });
});

// ─── Project CRUD ─────────────────────────────────────────────────

describe('Project — create', () => {
  it('should create a project within an org', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);
    const project = await db.createProject(org.id, 'my-project', identity.id);

    expect(project.id).toHaveLength(32);
    expect(project.name).toBe('my-project');
    expect(project.org_id).toBe(org.id);
    expect(project.created_at).toBeDefined();
  });

  it('should assign founder as project admin', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);
    const project = await db.createProject(org.id, 'my-project', identity.id);

    const members = db.listProjectMembers(project.id);
    expect(members).toHaveLength(1);
    expect(members[0].identity_id).toBe(identity.id);
    expect(members[0].role).toBe('admin');
  });

  it('should create a project without a founder', async () => {
    const org = await db.createOrg('acme');
    const project = await db.createProject(org.id, 'my-project');

    expect(project.name).toBe('my-project');
    expect(db.listProjectMembers(project.id)).toHaveLength(0);
  });

  it('should reject empty project name', async () => {
    const org = await db.createOrg('acme');
    await expect(db.createProject(org.id, '')).rejects.toThrow('Project name cannot be empty');
  });

  it('should reject project in nonexistent org', async () => {
    await expect(db.createProject('nonexistent', 'my-project')).rejects.toThrow(
      "Org 'nonexistent' not found"
    );
  });

  it('should reject duplicate project name within same org', async () => {
    const org = await db.createOrg('acme');
    await db.createProject(org.id, 'my-project');
    await expect(db.createProject(org.id, 'my-project')).rejects.toThrow(
      `Project 'my-project' already exists in org '${org.id}'`
    );
  });

  it('should allow same project name in different orgs', async () => {
    const org1 = await db.createOrg('acme');
    const org2 = await db.createOrg('globex');

    const p1 = await db.createProject(org1.id, 'my-project');
    const p2 = await db.createProject(org2.id, 'my-project');

    expect(p1.id).not.toBe(p2.id);
  });

  it('should reject founder who is not an org member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);

    await expect(db.createProject(org.id, 'my-project', bob.id)).rejects.toThrow(
      `Identity '${bob.id}' is not a member of org '${org.id}'`
    );
  });

  it('should reject readonly org member from creating projects', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: viewer } = await db.createIdentity('viewer', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, viewer.id, 'readonly');

    await expect(db.createProject(org.id, 'my-project', viewer.id)).rejects.toThrow(
      `Identity '${viewer.id}' has readonly role in org and cannot create projects`
    );
  });

  it('should allow member role to create projects', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');

    const project = await db.createProject(org.id, 'bob-project', bob.id);
    expect(project.name).toBe('bob-project');
  });
});

describe('Project — get & list', () => {
  it('should get project by ID', async () => {
    const org = await db.createOrg('acme');
    const project = await db.createProject(org.id, 'my-project');
    const found = db.getProject(project.id);

    expect(found).not.toBeNull();
    expect(found!.name).toBe('my-project');
    expect(found!.org_id).toBe(org.id);
  });

  it('should get project by name within org', async () => {
    const org = await db.createOrg('acme');
    await db.createProject(org.id, 'my-project');
    const found = db.getProjectByName(org.id, 'my-project');

    expect(found).not.toBeNull();
    expect(found!.name).toBe('my-project');
  });

  it('should return null for nonexistent project', () => {
    expect(db.getProject('nonexistent')).toBeNull();
  });

  it('should list projects in an org', async () => {
    const org = await db.createOrg('acme');
    await db.createProject(org.id, 'alpha');
    await db.createProject(org.id, 'beta');
    await db.createProject(org.id, 'gamma');

    const projects = db.listProjects(org.id);
    expect(projects).toHaveLength(3);
    expect(projects[0].name).toBe('alpha');
    expect(projects[1].name).toBe('beta');
    expect(projects[2].name).toBe('gamma');
  });

  it('should not list projects from other orgs', async () => {
    const org1 = await db.createOrg('acme');
    const org2 = await db.createOrg('globex');
    await db.createProject(org1.id, 'acme-project');
    await db.createProject(org2.id, 'globex-project');

    const acmeProjects = db.listProjects(org1.id);
    expect(acmeProjects).toHaveLength(1);
    expect(acmeProjects[0].name).toBe('acme-project');
  });
});

describe('Project — delete', () => {
  it('should delete a project', async () => {
    const org = await db.createOrg('acme');
    const project = await db.createProject(org.id, 'my-project');

    expect(db.deleteProject(project.id)).toBe(true);
    expect(db.getProject(project.id)).toBeNull();
  });

  it('should cascade-delete project memberships', async () => {
    const { identity } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', identity.id);
    const project = await db.createProject(org.id, 'my-project', identity.id);

    db.deleteProject(project.id);
    expect(db.getProjectMember(project.id, identity.id)).toBeNull();
  });

  it('should return false when deleting nonexistent project', () => {
    expect(db.deleteProject('nonexistent')).toBe(false);
  });
});

// ─── Project Membership ──────────────────────────────────────────

describe('Project — membership', () => {
  it('should add a member to a project', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');
    const project = await db.createProject(org.id, 'my-project', alice.id);

    db.addProjectMember(project.id, bob.id, 'member');

    const members = db.listProjectMembers(project.id);
    expect(members).toHaveLength(2);

    const bobMember = members.find(m => m.identity_id === bob.id);
    expect(bobMember).toBeDefined();
    expect(bobMember!.role).toBe('member');
  });

  it('should reject adding non-org-member to project', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: outsider } = await db.createIdentity('outsider', 'human');
    const org = await db.createOrg('acme', alice.id);
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(() => db.addProjectMember(project.id, outsider.id, 'member')).toThrow(
      `Identity '${outsider.id}' must be a member of org '${org.id}'`
    );
  });

  it('should reject adding member to nonexistent project', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    expect(() => db.addProjectMember('nonexistent', alice.id, 'member')).toThrow(
      "Project 'nonexistent' not found"
    );
  });

  it('should reject adding nonexistent identity to project', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id);
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(() => db.addProjectMember(project.id, 'nonexistent', 'member')).toThrow(
      "Identity 'nonexistent' not found"
    );
  });

  it('should reject duplicate project membership', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id);
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(() => db.addProjectMember(project.id, alice.id, 'member')).toThrow(
      `Identity '${alice.id}' is already a member of project '${project.id}'`
    );
  });

  it('should reject invalid project role', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(() => db.addProjectMember(project.id, bob.id, 'superadmin' as MemberRole)).toThrow(
      "Invalid role: 'superadmin'"
    );
  });

  it('should update project member role', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');
    const project = await db.createProject(org.id, 'my-project', alice.id);
    db.addProjectMember(project.id, bob.id, 'readonly');

    db.updateProjectMemberRole(project.id, bob.id, 'admin');

    const role = db.getProjectRole(project.id, bob.id);
    expect(role).toBe('admin');
  });

  it('should reject updating role for non-member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(() => db.updateProjectMemberRole(project.id, bob.id, 'admin')).toThrow(
      `Identity '${bob.id}' is not a member of project '${project.id}'`
    );
  });

  it('should remove a project member', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bob } = await db.createIdentity('bob', 'human');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bob.id, 'member');
    const project = await db.createProject(org.id, 'my-project', alice.id);
    db.addProjectMember(project.id, bob.id, 'member');

    expect(db.removeProjectMember(project.id, bob.id)).toBe(true);
    expect(db.getProjectRole(project.id, bob.id)).toBeNull();
  });

  it('should return false when removing non-member from project', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const org = await db.createOrg('acme', alice.id);
    const project = await db.createProject(org.id, 'my-project', alice.id);

    expect(db.removeProjectMember(project.id, 'nonexistent')).toBe(false);
  });

  it('should list project members with identity details', async () => {
    const { identity: alice } = await db.createIdentity('alice', 'human');
    const { identity: bot } = await db.createIdentity('ci-bot', 'agent');
    const org = await db.createOrg('acme', alice.id);
    db.addOrgMember(org.id, bot.id, 'member');
    const project = await db.createProject(org.id, 'my-project', alice.id);
    db.addProjectMember(project.id, bot.id, 'readonly');

    const members = db.listProjectMembers(project.id);
    expect(members).toHaveLength(2);

    for (const m of members) {
      expect(m.name).toBeDefined();
      expect(m.type).toBeDefined();
    }
  });
});

// ─── Integration: Full Workflow ────────────────────────────────────

describe('Identity — full workflow', () => {
  it('should support a complete identity -> org -> project -> membership flow', async () => {
    // Create identities
    const admin = await db.createIdentity('admin-user', 'human');
    const dev = await db.createIdentity('dev-agent', 'agent');
    const viewer = await db.createIdentity('viewer', 'human');

    // Create org with admin as founder
    const org = await db.createOrg('my-org', admin.identity.id);

    // Add members
    db.addOrgMember(org.id, dev.identity.id, 'member');
    db.addOrgMember(org.id, viewer.identity.id, 'readonly');

    // Verify org members
    expect(db.listOrgMembers(org.id)).toHaveLength(3);
    expect(db.getOrgRole(org.id, admin.identity.id)).toBe('admin');
    expect(db.getOrgRole(org.id, dev.identity.id)).toBe('member');
    expect(db.getOrgRole(org.id, viewer.identity.id)).toBe('readonly');

    // Create projects
    const prodProject = await db.createProject(org.id, 'production', admin.identity.id);
    const devProject = await db.createProject(org.id, 'development', dev.identity.id);

    // Add project members
    db.addProjectMember(prodProject.id, dev.identity.id, 'readonly');
    db.addProjectMember(devProject.id, admin.identity.id, 'admin');

    // Verify project members
    expect(db.listProjectMembers(prodProject.id)).toHaveLength(2);
    expect(db.getProjectRole(prodProject.id, admin.identity.id)).toBe('admin');
    expect(db.getProjectRole(prodProject.id, dev.identity.id)).toBe('readonly');

    expect(db.listProjectMembers(devProject.id)).toHaveLength(2);
    expect(db.getProjectRole(devProject.id, dev.identity.id)).toBe('admin');
    expect(db.getProjectRole(devProject.id, admin.identity.id)).toBe('admin');

    // Verify identities with private keys
    expect((await db.verifyIdentity(admin.privateKey))!.id).toBe(admin.identity.id);
    expect((await db.verifyIdentity(dev.privateKey))!.id).toBe(dev.identity.id);
    expect((await db.verifyIdentity(viewer.privateKey))!.id).toBe(viewer.identity.id);

    // List everything
    expect(db.listIdentities()).toHaveLength(3);
    expect(db.listOrgs()).toHaveLength(1);
    expect(db.listProjects(org.id)).toHaveLength(2);

    // Readonly viewer cannot create projects
    await expect(db.createProject(org.id, 'viewer-project', viewer.identity.id)).rejects.toThrow(
      'has readonly role'
    );
  });
});

// ─── Utility ──────────────────────────────────────────────────────

describe('getDefaultIdentityDbPath', () => {
  it('should return a path ending in identity.db', () => {
    const p = getDefaultIdentityDbPath();
    expect(p.endsWith('identity.db')).toBe(true);
    expect(p).toContain('.hq-vault');
  });
});
