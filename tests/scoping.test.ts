/**
 * Tests for secret scoping — US-002.
 *
 * Covers the full access control matrix:
 * - Path parsing (org-scoped, project-scoped, unscoped)
 * - Scope prefix builder
 * - Admin in org sees all secrets (org + all projects)
 * - Member in org sees org secrets, but only project secrets they're a member of
 * - Readonly in org can read but not write org secrets
 * - Project admin/member can read/write project secrets
 * - Project readonly can read but not write project secrets
 * - Non-member gets denied (403)
 * - Unscoped secrets denied for scoped identities (bootstrap-only)
 * - Access filtering for LIST operations
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  parseScope,
  buildScopedPath,
  checkAccess,
  filterAccessiblePaths,
} from '../src/scoping.js';
import { IdentityDatabase } from '../src/identity.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// ─── Test Helpers ─────────────────────────────────────────────────

let tmpDir: string;
let identityDb: IdentityDatabase;

async function createTestDb(): Promise<IdentityDatabase> {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-scoping-'));
  const dbPath = path.join(tmpDir, 'identity.db');
  return await IdentityDatabase.open(dbPath);
}

function cleanupTestDb(): void {
  if (identityDb) {
    try { identityDb.close(); } catch { /* already closed */ }
  }
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

beforeEach(async () => {
  identityDb = await createTestDb();
});

afterEach(() => {
  cleanupTestDb();
});

// ─── Path Parsing ─────────────────────────────────────────────────

describe('parseScope', () => {
  it('should parse org-scoped paths', () => {
    const result = parseScope('org/indigo/aws/key');
    expect(result.org).toBe('indigo');
    expect(result.project).toBeNull();
    expect(result.remainder).toBe('aws/key');
    expect(result.scoped).toBe(true);
  });

  it('should parse project-scoped paths', () => {
    const result = parseScope('org/indigo/project/hq-cloud/aws/key');
    expect(result.org).toBe('indigo');
    expect(result.project).toBe('hq-cloud');
    expect(result.remainder).toBe('aws/key');
    expect(result.scoped).toBe(true);
  });

  it('should parse org-only paths (no remainder)', () => {
    const result = parseScope('org/indigo');
    expect(result.org).toBe('indigo');
    expect(result.project).toBeNull();
    expect(result.remainder).toBe('');
    expect(result.scoped).toBe(true);
  });

  it('should parse project-only paths (no remainder)', () => {
    const result = parseScope('org/indigo/project/hq-cloud');
    expect(result.org).toBe('indigo');
    expect(result.project).toBe('hq-cloud');
    expect(result.remainder).toBe('');
    expect(result.scoped).toBe(true);
  });

  it('should identify unscoped paths', () => {
    const result = parseScope('local/my-key');
    expect(result.org).toBeNull();
    expect(result.project).toBeNull();
    expect(result.remainder).toBe('local/my-key');
    expect(result.scoped).toBe(false);
  });

  it('should handle paths that start with "org" but not "org/"', () => {
    const result = parseScope('organic/food');
    expect(result.scoped).toBe(false);
    expect(result.remainder).toBe('organic/food');
  });

  it('should handle deeply nested project paths', () => {
    const result = parseScope('org/acme/project/infra/cloud/aws/us-east-1/rds/password');
    expect(result.org).toBe('acme');
    expect(result.project).toBe('infra');
    expect(result.remainder).toBe('cloud/aws/us-east-1/rds/password');
    expect(result.scoped).toBe(true);
  });

  it('should handle org path with single segment remainder', () => {
    const result = parseScope('org/indigo/api-key');
    expect(result.org).toBe('indigo');
    expect(result.project).toBeNull();
    expect(result.remainder).toBe('api-key');
    expect(result.scoped).toBe(true);
  });
});

// ─── Scope Prefix Builder ────────────────────────────────────────

describe('buildScopedPath', () => {
  it('should build org-scoped path', () => {
    expect(buildScopedPath('indigo', null, 'aws/key')).toBe('org/indigo/aws/key');
  });

  it('should build project-scoped path', () => {
    expect(buildScopedPath('indigo', 'hq-cloud', 'aws/key')).toBe(
      'org/indigo/project/hq-cloud/aws/key'
    );
  });

  it('should build org-only path with empty key', () => {
    expect(buildScopedPath('indigo', null, '')).toBe('org/indigo');
  });

  it('should build project-only path with empty key', () => {
    expect(buildScopedPath('indigo', 'hq-cloud', '')).toBe('org/indigo/project/hq-cloud');
  });

  it('should roundtrip with parseScope', () => {
    const built = buildScopedPath('acme', 'infra', 'db/password');
    const parsed = parseScope(built);
    expect(parsed.org).toBe('acme');
    expect(parsed.project).toBe('infra');
    expect(parsed.remainder).toBe('db/password');
  });
});

// ─── Access Control Matrix ───────────────────────────────────────

describe('checkAccess — org-level secrets', () => {
  it('should allow org admin to read org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const result = checkAccess(identityDb, admin.id, 'org/indigo/api-key', 'read');
    expect(result.allowed).toBe(true);
  });

  it('should allow org admin to write org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const result = checkAccess(identityDb, admin.id, 'org/indigo/api-key', 'write');
    expect(result.allowed).toBe(true);
  });

  it('should allow org member to read org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: member } = await identityDb.createIdentity('member', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, member.id, 'member');

    const result = checkAccess(identityDb, member.id, 'org/indigo/api-key', 'read');
    expect(result.allowed).toBe(true);
  });

  it('should allow org member to write org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: member } = await identityDb.createIdentity('member', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, member.id, 'member');

    const result = checkAccess(identityDb, member.id, 'org/indigo/api-key', 'write');
    expect(result.allowed).toBe(true);
  });

  it('should allow org readonly to read org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: reader } = await identityDb.createIdentity('reader', 'agent');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, reader.id, 'readonly');

    const result = checkAccess(identityDb, reader.id, 'org/indigo/api-key', 'read');
    expect(result.allowed).toBe(true);
  });

  it('should deny org readonly from writing org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: reader } = await identityDb.createIdentity('reader', 'agent');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, reader.id, 'readonly');

    const result = checkAccess(identityDb, reader.id, 'org/indigo/api-key', 'write');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('readonly');
  });

  it('should deny non-member from reading org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: outsider } = await identityDb.createIdentity('outsider', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const result = checkAccess(identityDb, outsider.id, 'org/indigo/api-key', 'read');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('not a member');
  });

  it('should deny non-member from writing org secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: outsider } = await identityDb.createIdentity('outsider', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const result = checkAccess(identityDb, outsider.id, 'org/indigo/api-key', 'write');
    expect(result.allowed).toBe(false);
  });
});

describe('checkAccess — project-level secrets', () => {
  it('should allow org admin to read project secrets (even without project membership)', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    await identityDb.createProject(org.id, 'hq-cloud', admin.id);

    const result = checkAccess(
      identityDb, admin.id, 'org/indigo/project/hq-cloud/db/password', 'read'
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('Org admin');
  });

  it('should allow org admin to write project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    await identityDb.createProject(org.id, 'hq-cloud', admin.id);

    const result = checkAccess(
      identityDb, admin.id, 'org/indigo/project/hq-cloud/db/password', 'write'
    );
    expect(result.allowed).toBe(true);
  });

  it('should allow project member to read project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: dev } = await identityDb.createIdentity('dev', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, dev.id, 'member');
    const project = await identityDb.createProject(org.id, 'hq-cloud', admin.id);
    identityDb.addProjectMember(project.id, dev.id, 'member');

    const result = checkAccess(
      identityDb, dev.id, 'org/indigo/project/hq-cloud/db/password', 'read'
    );
    expect(result.allowed).toBe(true);
  });

  it('should allow project member to write project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: dev } = await identityDb.createIdentity('dev', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, dev.id, 'member');
    const project = await identityDb.createProject(org.id, 'hq-cloud', admin.id);
    identityDb.addProjectMember(project.id, dev.id, 'member');

    const result = checkAccess(
      identityDb, dev.id, 'org/indigo/project/hq-cloud/db/password', 'write'
    );
    expect(result.allowed).toBe(true);
  });

  it('should allow project readonly to read project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: viewer } = await identityDb.createIdentity('viewer', 'agent');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, viewer.id, 'member');
    const project = await identityDb.createProject(org.id, 'hq-cloud', admin.id);
    identityDb.addProjectMember(project.id, viewer.id, 'readonly');

    const result = checkAccess(
      identityDb, viewer.id, 'org/indigo/project/hq-cloud/db/password', 'read'
    );
    expect(result.allowed).toBe(true);
  });

  it('should deny project readonly from writing project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: viewer } = await identityDb.createIdentity('viewer', 'agent');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, viewer.id, 'member');
    const project = await identityDb.createProject(org.id, 'hq-cloud', admin.id);
    identityDb.addProjectMember(project.id, viewer.id, 'readonly');

    const result = checkAccess(
      identityDb, viewer.id, 'org/indigo/project/hq-cloud/db/password', 'write'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('readonly');
  });

  it('should deny org member without project membership from accessing project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: orgMember } = await identityDb.createIdentity('org-member', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, orgMember.id, 'member');
    await identityDb.createProject(org.id, 'hq-cloud', admin.id);

    const result = checkAccess(
      identityDb, orgMember.id, 'org/indigo/project/hq-cloud/db/password', 'read'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('not a member of project');
  });

  it('should deny non-member from accessing project secrets', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: outsider } = await identityDb.createIdentity('outsider', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    await identityDb.createProject(org.id, 'hq-cloud', admin.id);

    const result = checkAccess(
      identityDb, outsider.id, 'org/indigo/project/hq-cloud/db/password', 'read'
    );
    expect(result.allowed).toBe(false);
  });
});

describe('checkAccess — unscoped secrets', () => {
  it('should deny identity access to unscoped secrets', async () => {
    const { identity } = await identityDb.createIdentity('alice', 'human');
    await identityDb.createOrg('indigo', identity.id);

    const result = checkAccess(identityDb, identity.id, 'local/my-key', 'read');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('bootstrap token');
  });
});

describe('checkAccess — edge cases', () => {
  it('should deny access when org does not exist', async () => {
    const { identity } = await identityDb.createIdentity('alice', 'human');

    const result = checkAccess(identityDb, identity.id, 'org/nonexistent/api-key', 'read');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Org 'nonexistent' not found");
  });

  it('should deny access when project does not exist', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const result = checkAccess(
      identityDb, admin.id, 'org/indigo/project/nonexistent/key', 'read'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Project 'nonexistent' not found");
  });

  it('should handle admin access across multiple projects', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const org = await identityDb.createOrg('acme', admin.id);
    await identityDb.createProject(org.id, 'project-a');
    await identityDb.createProject(org.id, 'project-b');

    // Admin can access both projects
    expect(checkAccess(identityDb, admin.id, 'org/acme/project/project-a/key', 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, admin.id, 'org/acme/project/project-b/key', 'write').allowed).toBe(true);
  });

  it('should isolate access across orgs', async () => {
    const { identity: alice } = await identityDb.createIdentity('alice', 'human');
    const { identity: bob } = await identityDb.createIdentity('bob', 'human');
    await identityDb.createOrg('acme', alice.id);
    await identityDb.createOrg('globex', bob.id);

    // Alice cannot access Globex secrets
    expect(checkAccess(identityDb, alice.id, 'org/globex/api-key', 'read').allowed).toBe(false);
    // Bob cannot access Acme secrets
    expect(checkAccess(identityDb, bob.id, 'org/acme/api-key', 'read').allowed).toBe(false);
    // Each can access their own
    expect(checkAccess(identityDb, alice.id, 'org/acme/api-key', 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, bob.id, 'org/globex/api-key', 'read').allowed).toBe(true);
  });
});

// ─── List Filtering ─────────────────────────────────────────────

describe('filterAccessiblePaths', () => {
  it('should filter paths based on identity access', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: dev } = await identityDb.createIdentity('dev', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    identityDb.addOrgMember(org.id, dev.id, 'member');
    const projectA = await identityDb.createProject(org.id, 'alpha', admin.id);
    identityDb.addProjectMember(projectA.id, dev.id, 'member');
    await identityDb.createProject(org.id, 'beta', admin.id);
    // dev is NOT a member of project beta

    const allPaths = [
      'org/indigo/shared-key',                       // org-level — dev can see
      'org/indigo/project/alpha/db-password',         // project alpha — dev is member
      'org/indigo/project/beta/db-password',          // project beta — dev is NOT member
      'local/my-key',                                 // unscoped — dev cannot see
    ];

    const accessible = filterAccessiblePaths(identityDb, dev.id, allPaths);
    expect(accessible).toContain('org/indigo/shared-key');
    expect(accessible).toContain('org/indigo/project/alpha/db-password');
    expect(accessible).not.toContain('org/indigo/project/beta/db-password');
    expect(accessible).not.toContain('local/my-key');
    expect(accessible).toHaveLength(2);
  });

  it('should return all scoped paths for org admin', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    await identityDb.createProject(org.id, 'alpha');
    await identityDb.createProject(org.id, 'beta');

    const allPaths = [
      'org/indigo/shared-key',
      'org/indigo/project/alpha/db-password',
      'org/indigo/project/beta/db-password',
    ];

    const accessible = filterAccessiblePaths(identityDb, admin.id, allPaths);
    expect(accessible).toHaveLength(3);
  });

  it('should return empty list for non-member', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    const { identity: outsider } = await identityDb.createIdentity('outsider', 'human');
    const org = await identityDb.createOrg('indigo', admin.id);
    await identityDb.createProject(org.id, 'alpha');

    const allPaths = [
      'org/indigo/shared-key',
      'org/indigo/project/alpha/db-password',
    ];

    const accessible = filterAccessiblePaths(identityDb, outsider.id, allPaths);
    expect(accessible).toHaveLength(0);
  });

  it('should handle empty path list', async () => {
    const { identity: admin } = await identityDb.createIdentity('admin', 'human');
    await identityDb.createOrg('indigo', admin.id);

    const accessible = filterAccessiblePaths(identityDb, admin.id, []);
    expect(accessible).toHaveLength(0);
  });
});

// ─── Integration: Full Access Control Matrix ─────────────────────

describe('Access control matrix — full scenario', () => {
  it('should enforce the complete access control matrix across roles', async () => {
    // Setup: org with admin, member, readonly, and an outsider
    const { identity: orgAdmin } = await identityDb.createIdentity('org-admin', 'human');
    const { identity: orgMember } = await identityDb.createIdentity('org-member', 'human');
    const { identity: orgReadonly } = await identityDb.createIdentity('org-readonly', 'agent');
    const { identity: projectMember } = await identityDb.createIdentity('project-member', 'human');
    const { identity: projectReadonly } = await identityDb.createIdentity('project-readonly', 'agent');
    const { identity: outsider } = await identityDb.createIdentity('outsider', 'human');

    const org = await identityDb.createOrg('acme', orgAdmin.id);
    identityDb.addOrgMember(org.id, orgMember.id, 'member');
    identityDb.addOrgMember(org.id, orgReadonly.id, 'readonly');
    identityDb.addOrgMember(org.id, projectMember.id, 'member');
    identityDb.addOrgMember(org.id, projectReadonly.id, 'member');

    const project = await identityDb.createProject(org.id, 'infra', orgAdmin.id);
    identityDb.addProjectMember(project.id, projectMember.id, 'member');
    identityDb.addProjectMember(project.id, projectReadonly.id, 'readonly');

    const orgSecret = 'org/acme/shared-api-key';
    const projectSecret = 'org/acme/project/infra/db-password';

    // ── Org Admin ─────────────────────────────────────────────
    expect(checkAccess(identityDb, orgAdmin.id, orgSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, orgAdmin.id, orgSecret, 'write').allowed).toBe(true);
    expect(checkAccess(identityDb, orgAdmin.id, projectSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, orgAdmin.id, projectSecret, 'write').allowed).toBe(true);

    // ── Org Member ────────────────────────────────────────────
    expect(checkAccess(identityDb, orgMember.id, orgSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, orgMember.id, orgSecret, 'write').allowed).toBe(true);
    // Org member without project membership cannot access project secrets
    expect(checkAccess(identityDb, orgMember.id, projectSecret, 'read').allowed).toBe(false);
    expect(checkAccess(identityDb, orgMember.id, projectSecret, 'write').allowed).toBe(false);

    // ── Org Readonly ──────────────────────────────────────────
    expect(checkAccess(identityDb, orgReadonly.id, orgSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, orgReadonly.id, orgSecret, 'write').allowed).toBe(false);
    // Org readonly without project membership cannot access project secrets
    expect(checkAccess(identityDb, orgReadonly.id, projectSecret, 'read').allowed).toBe(false);
    expect(checkAccess(identityDb, orgReadonly.id, projectSecret, 'write').allowed).toBe(false);

    // ── Project Member ────────────────────────────────────────
    expect(checkAccess(identityDb, projectMember.id, orgSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, projectMember.id, orgSecret, 'write').allowed).toBe(true);
    expect(checkAccess(identityDb, projectMember.id, projectSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, projectMember.id, projectSecret, 'write').allowed).toBe(true);

    // ── Project Readonly ──────────────────────────────────────
    expect(checkAccess(identityDb, projectReadonly.id, orgSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, projectReadonly.id, orgSecret, 'write').allowed).toBe(true);
    expect(checkAccess(identityDb, projectReadonly.id, projectSecret, 'read').allowed).toBe(true);
    expect(checkAccess(identityDb, projectReadonly.id, projectSecret, 'write').allowed).toBe(false);

    // ── Outsider ──────────────────────────────────────────────
    expect(checkAccess(identityDb, outsider.id, orgSecret, 'read').allowed).toBe(false);
    expect(checkAccess(identityDb, outsider.id, orgSecret, 'write').allowed).toBe(false);
    expect(checkAccess(identityDb, outsider.id, projectSecret, 'read').allowed).toBe(false);
    expect(checkAccess(identityDb, outsider.id, projectSecret, 'write').allowed).toBe(false);
  });
});
