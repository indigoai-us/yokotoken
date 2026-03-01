/**
 * Identity module for hq-vault — US-001.
 *
 * Provides a standalone identity system with org/project tenancy:
 * - Identities (human or agent) with Ed25519 keypairs
 * - Organizations with admin/member/readonly roles
 * - Projects scoped to organizations
 * - Membership management with role enforcement
 *
 * Uses a SEPARATE SQLite database (identity.db) from the vault secrets database.
 * Private keys are NEVER stored — only the public key hash is persisted.
 */

import Database from 'better-sqlite3';
import sodium from 'sodium-native';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';

// ─── Types ──────────────────────────────────────────────────────────

export type IdentityType = 'human' | 'agent';
export type MemberRole = 'admin' | 'member' | 'readonly';

export interface Identity {
  id: string;
  name: string;
  type: IdentityType;
  public_key_hash: string;
  created_at: string;
}

export interface Org {
  id: string;
  name: string;
  created_at: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  created_at: string;
}

export interface OrgMember {
  identity_id: string;
  org_id: string;
  role: MemberRole;
}

export interface ProjectMember {
  identity_id: string;
  project_id: string;
  role: MemberRole;
}

export interface IdentityCreateResult {
  identity: Identity;
  /** The raw Ed25519 private key (64 bytes, base64). Shown ONCE, never stored. */
  privateKey: string;
  /** The raw Ed25519 public key (32 bytes, base64). */
  publicKey: string;
}

// ─── Constants ──────────────────────────────────────────────────────

const VALID_IDENTITY_TYPES: IdentityType[] = ['human', 'agent'];
const VALID_ROLES: MemberRole[] = ['admin', 'member', 'readonly'];

// ─── IdentityDatabase ───────────────────────────────────────────────

export class IdentityDatabase {
  private db: Database.Database;

  constructor(dbPath: string) {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    this.initSchema();
  }

  /**
   * Initialize identity database schema.
   */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS identities (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        type            TEXT NOT NULL CHECK(type IN ('human', 'agent')),
        public_key_hash TEXT NOT NULL UNIQUE,
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS orgs (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS projects (
        id         TEXT PRIMARY KEY,
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(org_id, name)
      );

      CREATE TABLE IF NOT EXISTS org_members (
        identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        role        TEXT NOT NULL CHECK(role IN ('admin', 'member', 'readonly')),
        PRIMARY KEY (identity_id, org_id)
      );

      CREATE TABLE IF NOT EXISTS project_members (
        identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
        project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        role        TEXT NOT NULL CHECK(role IN ('admin', 'member', 'readonly')),
        PRIMARY KEY (identity_id, project_id)
      );

      CREATE INDEX IF NOT EXISTS idx_projects_org_id ON projects(org_id);
      CREATE INDEX IF NOT EXISTS idx_org_members_org_id ON org_members(org_id);
      CREATE INDEX IF NOT EXISTS idx_org_members_identity_id ON org_members(identity_id);
      CREATE INDEX IF NOT EXISTS idx_project_members_project_id ON project_members(project_id);
      CREATE INDEX IF NOT EXISTS idx_project_members_identity_id ON project_members(identity_id);
    `);
  }

  // ─── Identity CRUD ──────────────────────────────────────────────

  /**
   * Create a new identity with an Ed25519 keypair.
   *
   * Generates a keypair, stores the public key hash, and returns
   * the private key for one-time display. The private key is NEVER stored.
   */
  createIdentity(name: string, type: IdentityType): IdentityCreateResult {
    if (!name || name.trim().length === 0) {
      throw new Error('Identity name cannot be empty');
    }
    if (!VALID_IDENTITY_TYPES.includes(type)) {
      throw new Error(`Invalid identity type: '${type}'. Must be 'human' or 'agent'`);
    }

    // Generate Ed25519 keypair using sodium-native
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
    sodium.crypto_sign_keypair(publicKey, secretKey);

    // Hash the public key for storage (SHA-256 hex)
    const publicKeyHash = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex');

    const id = generateId();

    this.db.prepare(`
      INSERT INTO identities (id, name, type, public_key_hash)
      VALUES (?, ?, ?, ?)
    `).run(id, name.trim(), type, publicKeyHash);

    const identity = this.getIdentity(id)!;

    const result: IdentityCreateResult = {
      identity,
      privateKey: secretKey.toString('base64'),
      publicKey: publicKey.toString('base64'),
    };

    // Zero out the secret key buffer after copying to base64
    sodium.sodium_memzero(secretKey);

    return result;
  }

  /**
   * Get an identity by ID.
   */
  getIdentity(id: string): Identity | null {
    const row = this.db.prepare(
      'SELECT * FROM identities WHERE id = ?'
    ).get(id) as Identity | undefined;
    return row ?? null;
  }

  /**
   * Get an identity by name.
   */
  getIdentityByName(name: string): Identity | null {
    const row = this.db.prepare(
      'SELECT * FROM identities WHERE name = ?'
    ).get(name) as Identity | undefined;
    return row ?? null;
  }

  /**
   * List all identities.
   */
  listIdentities(): Identity[] {
    return this.db.prepare(
      'SELECT * FROM identities ORDER BY created_at'
    ).all() as Identity[];
  }

  /**
   * Delete an identity by ID. Also removes all memberships (via CASCADE).
   */
  deleteIdentity(id: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM identities WHERE id = ?'
    ).run(id);
    return result.changes > 0;
  }

  // ─── Org CRUD ───────────────────────────────────────────────────

  /**
   * Create a new organization.
   * Optionally assigns a founding identity as admin.
   */
  createOrg(name: string, founderIdentityId?: string): Org {
    if (!name || name.trim().length === 0) {
      throw new Error('Org name cannot be empty');
    }

    // Check for duplicate name
    const existing = this.getOrgByName(name.trim());
    if (existing) {
      throw new Error(`Org '${name.trim()}' already exists`);
    }

    // Validate founder identity exists (if provided)
    if (founderIdentityId) {
      const identity = this.getIdentity(founderIdentityId);
      if (!identity) {
        throw new Error(`Identity '${founderIdentityId}' not found`);
      }
    }

    const id = generateId();

    const insertOrg = this.db.prepare(`
      INSERT INTO orgs (id, name) VALUES (?, ?)
    `);

    const insertMember = this.db.prepare(`
      INSERT INTO org_members (identity_id, org_id, role) VALUES (?, ?, 'admin')
    `);

    const transaction = this.db.transaction(() => {
      insertOrg.run(id, name.trim());
      if (founderIdentityId) {
        insertMember.run(founderIdentityId, id);
      }
    });

    transaction();

    return this.getOrg(id)!;
  }

  /**
   * Get an org by ID.
   */
  getOrg(id: string): Org | null {
    const row = this.db.prepare(
      'SELECT * FROM orgs WHERE id = ?'
    ).get(id) as Org | undefined;
    return row ?? null;
  }

  /**
   * Get an org by name.
   */
  getOrgByName(name: string): Org | null {
    const row = this.db.prepare(
      'SELECT * FROM orgs WHERE name = ?'
    ).get(name) as Org | undefined;
    return row ?? null;
  }

  /**
   * List all organizations.
   */
  listOrgs(): Org[] {
    return this.db.prepare(
      'SELECT * FROM orgs ORDER BY created_at'
    ).all() as Org[];
  }

  /**
   * Delete an org by ID. Also deletes all projects and memberships (via CASCADE).
   */
  deleteOrg(id: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM orgs WHERE id = ?'
    ).run(id);
    return result.changes > 0;
  }

  // ─── Org Membership ─────────────────────────────────────────────

  /**
   * Add a member to an organization with a specified role.
   */
  addOrgMember(orgId: string, identityId: string, role: MemberRole): void {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid role: '${role}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const org = this.getOrg(orgId);
    if (!org) {
      throw new Error(`Org '${orgId}' not found`);
    }

    const identity = this.getIdentity(identityId);
    if (!identity) {
      throw new Error(`Identity '${identityId}' not found`);
    }

    // Check if already a member
    const existing = this.getOrgMember(orgId, identityId);
    if (existing) {
      throw new Error(`Identity '${identityId}' is already a member of org '${orgId}'`);
    }

    this.db.prepare(`
      INSERT INTO org_members (identity_id, org_id, role) VALUES (?, ?, ?)
    `).run(identityId, orgId, role);
  }

  /**
   * Update an org member's role.
   */
  updateOrgMemberRole(orgId: string, identityId: string, newRole: MemberRole): void {
    if (!VALID_ROLES.includes(newRole)) {
      throw new Error(`Invalid role: '${newRole}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const result = this.db.prepare(`
      UPDATE org_members SET role = ? WHERE org_id = ? AND identity_id = ?
    `).run(newRole, orgId, identityId);

    if (result.changes === 0) {
      throw new Error(`Identity '${identityId}' is not a member of org '${orgId}'`);
    }
  }

  /**
   * Remove a member from an organization.
   */
  removeOrgMember(orgId: string, identityId: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM org_members WHERE org_id = ? AND identity_id = ?'
    ).run(orgId, identityId);
    return result.changes > 0;
  }

  /**
   * Get an org membership record.
   */
  getOrgMember(orgId: string, identityId: string): OrgMember | null {
    const row = this.db.prepare(
      'SELECT * FROM org_members WHERE org_id = ? AND identity_id = ?'
    ).get(orgId, identityId) as OrgMember | undefined;
    return row ?? null;
  }

  /**
   * List all members of an organization.
   */
  listOrgMembers(orgId: string): (OrgMember & { name: string; type: IdentityType })[] {
    return this.db.prepare(`
      SELECT om.identity_id, om.org_id, om.role, i.name, i.type
      FROM org_members om
      JOIN identities i ON i.id = om.identity_id
      WHERE om.org_id = ?
      ORDER BY om.role, i.name
    `).all(orgId) as (OrgMember & { name: string; type: IdentityType })[];
  }

  /**
   * Get the role of an identity in an org. Returns null if not a member.
   */
  getOrgRole(orgId: string, identityId: string): MemberRole | null {
    const member = this.getOrgMember(orgId, identityId);
    return member?.role ?? null;
  }

  // ─── Project CRUD ───────────────────────────────────────────────

  /**
   * Create a new project within an organization.
   * Optionally assigns a founding identity as admin.
   */
  createProject(orgId: string, name: string, founderIdentityId?: string): Project {
    if (!name || name.trim().length === 0) {
      throw new Error('Project name cannot be empty');
    }

    const org = this.getOrg(orgId);
    if (!org) {
      throw new Error(`Org '${orgId}' not found`);
    }

    // Validate founder identity exists and is an org member (if provided)
    if (founderIdentityId) {
      const identity = this.getIdentity(founderIdentityId);
      if (!identity) {
        throw new Error(`Identity '${founderIdentityId}' not found`);
      }
      const orgRole = this.getOrgRole(orgId, founderIdentityId);
      if (!orgRole) {
        throw new Error(`Identity '${founderIdentityId}' is not a member of org '${orgId}'`);
      }
      if (orgRole === 'readonly') {
        throw new Error(`Identity '${founderIdentityId}' has readonly role in org and cannot create projects`);
      }
    }

    // Check for duplicate name within the org
    const existing = this.getProjectByName(orgId, name.trim());
    if (existing) {
      throw new Error(`Project '${name.trim()}' already exists in org '${orgId}'`);
    }

    const id = generateId();

    const insertProject = this.db.prepare(`
      INSERT INTO projects (id, org_id, name) VALUES (?, ?, ?)
    `);

    const insertMember = this.db.prepare(`
      INSERT INTO project_members (identity_id, project_id, role) VALUES (?, ?, 'admin')
    `);

    const transaction = this.db.transaction(() => {
      insertProject.run(id, orgId, name.trim());
      if (founderIdentityId) {
        insertMember.run(founderIdentityId, id);
      }
    });

    transaction();

    return this.getProject(id)!;
  }

  /**
   * Get a project by ID.
   */
  getProject(id: string): Project | null {
    const row = this.db.prepare(
      'SELECT * FROM projects WHERE id = ?'
    ).get(id) as Project | undefined;
    return row ?? null;
  }

  /**
   * Get a project by name within an org.
   */
  getProjectByName(orgId: string, name: string): Project | null {
    const row = this.db.prepare(
      'SELECT * FROM projects WHERE org_id = ? AND name = ?'
    ).get(orgId, name) as Project | undefined;
    return row ?? null;
  }

  /**
   * List all projects in an organization.
   */
  listProjects(orgId: string): Project[] {
    return this.db.prepare(
      'SELECT * FROM projects WHERE org_id = ? ORDER BY created_at'
    ).all(orgId) as Project[];
  }

  /**
   * Delete a project by ID. Also removes all memberships (via CASCADE).
   */
  deleteProject(id: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM projects WHERE id = ?'
    ).run(id);
    return result.changes > 0;
  }

  // ─── Project Membership ─────────────────────────────────────────

  /**
   * Add a member to a project with a specified role.
   * The identity must be a member of the project's parent org.
   */
  addProjectMember(projectId: string, identityId: string, role: MemberRole): void {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid role: '${role}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const project = this.getProject(projectId);
    if (!project) {
      throw new Error(`Project '${projectId}' not found`);
    }

    const identity = this.getIdentity(identityId);
    if (!identity) {
      throw new Error(`Identity '${identityId}' not found`);
    }

    // Verify the identity is a member of the parent org
    const orgRole = this.getOrgRole(project.org_id, identityId);
    if (!orgRole) {
      throw new Error(
        `Identity '${identityId}' must be a member of org '${project.org_id}' before being added to a project`
      );
    }

    // Check if already a project member
    const existing = this.getProjectMember(projectId, identityId);
    if (existing) {
      throw new Error(`Identity '${identityId}' is already a member of project '${projectId}'`);
    }

    this.db.prepare(`
      INSERT INTO project_members (identity_id, project_id, role) VALUES (?, ?, ?)
    `).run(identityId, projectId, role);
  }

  /**
   * Update a project member's role.
   */
  updateProjectMemberRole(projectId: string, identityId: string, newRole: MemberRole): void {
    if (!VALID_ROLES.includes(newRole)) {
      throw new Error(`Invalid role: '${newRole}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const result = this.db.prepare(`
      UPDATE project_members SET role = ? WHERE project_id = ? AND identity_id = ?
    `).run(newRole, projectId, identityId);

    if (result.changes === 0) {
      throw new Error(`Identity '${identityId}' is not a member of project '${projectId}'`);
    }
  }

  /**
   * Remove a member from a project.
   */
  removeProjectMember(projectId: string, identityId: string): boolean {
    const result = this.db.prepare(
      'DELETE FROM project_members WHERE project_id = ? AND identity_id = ?'
    ).run(projectId, identityId);
    return result.changes > 0;
  }

  /**
   * Get a project membership record.
   */
  getProjectMember(projectId: string, identityId: string): ProjectMember | null {
    const row = this.db.prepare(
      'SELECT * FROM project_members WHERE project_id = ? AND identity_id = ?'
    ).get(projectId, identityId) as ProjectMember | undefined;
    return row ?? null;
  }

  /**
   * List all members of a project.
   */
  listProjectMembers(projectId: string): (ProjectMember & { name: string; type: IdentityType })[] {
    return this.db.prepare(`
      SELECT pm.identity_id, pm.project_id, pm.role, i.name, i.type
      FROM project_members pm
      JOIN identities i ON i.id = pm.identity_id
      WHERE pm.project_id = ?
      ORDER BY pm.role, i.name
    `).all(projectId) as (ProjectMember & { name: string; type: IdentityType })[];
  }

  /**
   * Get the role of an identity in a project. Returns null if not a member.
   */
  getProjectRole(projectId: string, identityId: string): MemberRole | null {
    const member = this.getProjectMember(projectId, identityId);
    return member?.role ?? null;
  }

  // ─── Utility ────────────────────────────────────────────────────

  /**
   * Verify that a private key corresponds to a stored identity.
   * Returns the identity if the key matches, null otherwise.
   */
  verifyIdentity(privateKeyBase64: string): Identity | null {
    try {
      const secretKey = Buffer.from(privateKeyBase64, 'base64');
      if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
        return null;
      }

      // Extract the public key from the secret key
      const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
      sodium.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);

      // Hash and look up
      const publicKeyHash = crypto
        .createHash('sha256')
        .update(publicKey)
        .digest('hex');

      const row = this.db.prepare(
        'SELECT * FROM identities WHERE public_key_hash = ?'
      ).get(publicKeyHash) as Identity | undefined;

      // Zero out the secret key
      sodium.sodium_memzero(secretKey);

      return row ?? null;
    } catch {
      return null;
    }
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }
}

// ─── Helpers ──────────────────────────────────────────────────────

/**
 * Generate a random ID (16 bytes, hex encoded = 32 chars).
 */
function generateId(): string {
  const buf = Buffer.alloc(16);
  sodium.randombytes_buf(buf);
  return buf.toString('hex');
}

/**
 * Get the default identity database path.
 */
export function getDefaultIdentityDbPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.hq-vault', 'identity.db');
}
