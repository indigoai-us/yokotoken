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
 *
 * Uses sql.js (WASM) and libsodium-wrappers-sumo (WASM) for portability.
 */

import initSqlJs, { type Database as SqlJsDatabase } from 'sql.js';
import sodium from 'libsodium-wrappers-sumo';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { ensureSodium } from './crypto.js';

// ─── Types ──────────────────────────────────────────────────────────

export type IdentityType = 'human' | 'agent';
export type MemberRole = 'admin' | 'member' | 'readonly';

export interface Identity {
  id: string;
  name: string;
  type: IdentityType;
  public_key_hash: string;
  created_at: string;
  /** Previous public key hash (set during key rotation with grace period). */
  old_public_key_hash: string | null;
  /** When the old key expires (ISO 8601). Null if no grace period active. */
  old_key_expires_at: string | null;
}

export interface KeyRotationResult {
  identity: Identity;
  /** The new Ed25519 private key (64 bytes, base64). Shown ONCE, never stored. */
  privateKey: string;
  /** The new Ed25519 public key (32 bytes, base64). */
  publicKey: string;
  /** The old public key hash (prefix only, for reference). */
  oldKeyHashPrefix: string;
  /** The new public key hash (prefix only, for reference). */
  newKeyHashPrefix: string;
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

/** Cached sql.js SQL module (loaded once). */
let sqlJsModule: Awaited<ReturnType<typeof initSqlJs>> | null = null;

async function getSqlJs() {
  if (!sqlJsModule) {
    sqlJsModule = await initSqlJs();
  }
  return sqlJsModule;
}

// ─── IdentityDatabase ───────────────────────────────────────────────

export class IdentityDatabase {
  private db: SqlJsDatabase;
  private dbPath: string;

  /** Use IdentityDatabase.open(dbPath) instead of constructor. */
  private constructor(db: SqlJsDatabase, dbPath: string) {
    this.db = db;
    this.dbPath = dbPath;
  }

  /**
   * Open or create an identity database at the given path.
   */
  static async open(dbPath: string): Promise<IdentityDatabase> {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const SQL = await getSqlJs();

    let db: SqlJsDatabase;
    if (fs.existsSync(dbPath)) {
      const fileBuffer = fs.readFileSync(dbPath);
      db = new SQL.Database(fileBuffer);
    } else {
      db = new SQL.Database();
    }

    db.run('PRAGMA foreign_keys = ON');

    const instance = new IdentityDatabase(db, dbPath);
    instance.initSchema();
    instance.migrateSchema();

    // Re-enable foreign keys after schema init — sql.js multi-statement
    // db.run() can reset connection-level PRAGMAs.
    db.run('PRAGMA foreign_keys = ON');

    instance.save();
    return instance;
  }

  /**
   * Persist to disk.
   *
   * Note: sql.js `db.export()` resets connection-level PRAGMAs (including
   * foreign_keys) as a side-effect, so we re-enable foreign keys after export.
   */
  private save(): void {
    const data = this.db.export();
    fs.writeFileSync(this.dbPath, Buffer.from(data));
    this.db.run('PRAGMA foreign_keys = ON');
  }

  /**
   * Initialize identity database schema.
   */
  private initSchema(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS identities (
        id                   TEXT PRIMARY KEY,
        name                 TEXT NOT NULL,
        type                 TEXT NOT NULL CHECK(type IN ('human', 'agent')),
        public_key_hash      TEXT NOT NULL UNIQUE,
        created_at           TEXT NOT NULL DEFAULT (datetime('now')),
        old_public_key_hash  TEXT,
        old_key_expires_at   TEXT
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

  /**
   * Migrate schema for existing databases (add columns if missing).
   */
  private migrateSchema(): void {
    const colNames = new Set<string>();
    const stmt = this.db.prepare('PRAGMA table_info(identities)');
    while (stmt.step()) {
      const row = stmt.getAsObject();
      colNames.add(row.name as string);
    }
    stmt.free();

    if (!colNames.has('old_public_key_hash')) {
      this.db.run(`ALTER TABLE identities ADD COLUMN old_public_key_hash TEXT`);
    }
    if (!colNames.has('old_key_expires_at')) {
      this.db.run(`ALTER TABLE identities ADD COLUMN old_key_expires_at TEXT`);
    }
  }

  // ─── Identity CRUD ──────────────────────────────────────────────

  /**
   * Create a new identity with an Ed25519 keypair.
   *
   * Generates a keypair, stores the public key hash, and returns
   * the private key for one-time display. The private key is NEVER stored.
   */
  async createIdentity(name: string, type: IdentityType): Promise<IdentityCreateResult> {
    if (!name || name.trim().length === 0) {
      throw new Error('Identity name cannot be empty');
    }
    if (!VALID_IDENTITY_TYPES.includes(type)) {
      throw new Error(`Invalid identity type: '${type}'. Must be 'human' or 'agent'`);
    }

    await ensureSodium();

    // Generate Ed25519 keypair using libsodium-wrappers-sumo
    const keypair = sodium.crypto_sign_keypair();
    const publicKey = Buffer.from(keypair.publicKey);
    const secretKey = Buffer.from(keypair.privateKey);

    // Hash the public key for storage (SHA-256 hex)
    const publicKeyHash = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex');

    const id = await generateId();

    this.db.run(
      `INSERT INTO identities (id, name, type, public_key_hash)
      VALUES (?, ?, ?, ?)`,
      [id, name.trim(), type, publicKeyHash],
    );
    this.save();

    const identity = this.getIdentity(id)!;

    const result: IdentityCreateResult = {
      identity,
      privateKey: secretKey.toString('base64'),
      publicKey: publicKey.toString('base64'),
    };

    // Zero out the secret key buffer after copying to base64
    sodium.memzero(secretKey);

    return result;
  }

  /**
   * Get an identity by ID.
   */
  getIdentity(id: string): Identity | null {
    const stmt = this.db.prepare('SELECT * FROM identities WHERE id = ?');
    stmt.bind([id]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toIdentity(row);
    }
    stmt.free();
    return null;
  }

  /**
   * Get an identity by name.
   */
  getIdentityByName(name: string): Identity | null {
    const stmt = this.db.prepare('SELECT * FROM identities WHERE name = ?');
    stmt.bind([name]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toIdentity(row);
    }
    stmt.free();
    return null;
  }

  /**
   * List all identities.
   */
  listIdentities(): Identity[] {
    const results: Identity[] = [];
    const stmt = this.db.prepare('SELECT * FROM identities ORDER BY created_at');
    while (stmt.step()) {
      results.push(this.toIdentity(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  /**
   * Delete an identity by ID. Also removes all memberships (via CASCADE).
   */
  deleteIdentity(id: string): boolean {
    const exists = this.getIdentity(id);
    if (!exists) return false;
    this.db.run('DELETE FROM identities WHERE id = ?', [id]);
    this.save();
    return true;
  }

  // ─── Key Rotation ──────────────────────────────────────────────

  /**
   * Rotate an identity's Ed25519 keypair.
   */
  async rotateKey(identityId: string, gracePeriodMs?: number): Promise<KeyRotationResult> {
    const identity = this.getIdentity(identityId);
    if (!identity) {
      throw new Error(`Identity '${identityId}' not found`);
    }

    await ensureSodium();

    const oldKeyHash = identity.public_key_hash;

    // Generate new Ed25519 keypair
    const keypair = sodium.crypto_sign_keypair();
    const publicKey = Buffer.from(keypair.publicKey);
    const secretKey = Buffer.from(keypair.privateKey);

    // Hash the new public key
    const newKeyHash = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex');

    // Set grace period fields
    let oldKeyExpiresAt: string | null = null;
    let oldPublicKeyHash: string | null = null;

    if (gracePeriodMs && gracePeriodMs > 0) {
      oldPublicKeyHash = oldKeyHash;
      oldKeyExpiresAt = new Date(Date.now() + gracePeriodMs).toISOString();
    }

    // Update the identity in the database
    this.db.run(
      `UPDATE identities
      SET public_key_hash = ?,
          old_public_key_hash = ?,
          old_key_expires_at = ?
      WHERE id = ?`,
      [newKeyHash, oldPublicKeyHash, oldKeyExpiresAt, identityId],
    );
    this.save();

    const updatedIdentity = this.getIdentity(identityId)!;

    const result: KeyRotationResult = {
      identity: updatedIdentity,
      privateKey: secretKey.toString('base64'),
      publicKey: publicKey.toString('base64'),
      oldKeyHashPrefix: oldKeyHash.substring(0, 12),
      newKeyHashPrefix: newKeyHash.substring(0, 12),
    };

    // Zero out the secret key buffer
    sodium.memzero(secretKey);

    return result;
  }

  /**
   * Check if a public key hash is valid for an identity.
   */
  isValidKeyHash(identityId: string, keyHash: string): boolean {
    const identity = this.getIdentity(identityId);
    if (!identity) return false;

    // Check current key
    if (identity.public_key_hash === keyHash) return true;

    // Check old key within grace period
    if (
      identity.old_public_key_hash &&
      identity.old_public_key_hash === keyHash &&
      identity.old_key_expires_at
    ) {
      const expiresAt = new Date(identity.old_key_expires_at).getTime();
      if (Date.now() <= expiresAt) {
        return true;
      }
    }

    return false;
  }

  /**
   * Clear expired old key hashes.
   */
  clearExpiredOldKeys(): number {
    const nowIso = new Date().toISOString();
    // Count matching rows first
    const countStmt = this.db.prepare(
      `SELECT COUNT(*) as c FROM identities WHERE old_key_expires_at IS NOT NULL AND old_key_expires_at < ?`,
    );
    countStmt.bind([nowIso]);
    countStmt.step();
    const count = (countStmt.getAsObject().c as number) || 0;
    countStmt.free();

    if (count > 0) {
      this.db.run(
        `UPDATE identities
        SET old_public_key_hash = NULL, old_key_expires_at = NULL
        WHERE old_key_expires_at IS NOT NULL
          AND old_key_expires_at < ?`,
        [nowIso],
      );
      this.save();
    }
    return count;
  }

  // ─── Org CRUD ───────────────────────────────────────────────────

  /**
   * Create a new organization.
   * Optionally assigns a founding identity as admin.
   */
  async createOrg(name: string, founderIdentityId?: string): Promise<Org> {
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

    const id = await generateId();

    this.db.run(
      `INSERT INTO orgs (id, name) VALUES (?, ?)`,
      [id, name.trim()],
    );

    if (founderIdentityId) {
      this.db.run(
        `INSERT INTO org_members (identity_id, org_id, role) VALUES (?, ?, 'admin')`,
        [founderIdentityId, id],
      );
    }

    this.save();
    return this.getOrg(id)!;
  }

  /**
   * Get an org by ID.
   */
  getOrg(id: string): Org | null {
    const stmt = this.db.prepare('SELECT * FROM orgs WHERE id = ?');
    stmt.bind([id]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as Org;
    }
    stmt.free();
    return null;
  }

  /**
   * Get an org by name.
   */
  getOrgByName(name: string): Org | null {
    const stmt = this.db.prepare('SELECT * FROM orgs WHERE name = ?');
    stmt.bind([name]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as Org;
    }
    stmt.free();
    return null;
  }

  /**
   * List all organizations.
   */
  listOrgs(): Org[] {
    const results: Org[] = [];
    const stmt = this.db.prepare('SELECT * FROM orgs ORDER BY created_at');
    while (stmt.step()) {
      results.push(stmt.getAsObject() as unknown as Org);
    }
    stmt.free();
    return results;
  }

  /**
   * Delete an org by ID.
   */
  deleteOrg(id: string): boolean {
    const exists = this.getOrg(id);
    if (!exists) return false;
    this.db.run('DELETE FROM orgs WHERE id = ?', [id]);
    this.save();
    return true;
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

    this.db.run(
      `INSERT INTO org_members (identity_id, org_id, role) VALUES (?, ?, ?)`,
      [identityId, orgId, role],
    );
    this.save();
  }

  /**
   * Update an org member's role.
   */
  updateOrgMemberRole(orgId: string, identityId: string, newRole: MemberRole): void {
    if (!VALID_ROLES.includes(newRole)) {
      throw new Error(`Invalid role: '${newRole}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const existing = this.getOrgMember(orgId, identityId);
    if (!existing) {
      throw new Error(`Identity '${identityId}' is not a member of org '${orgId}'`);
    }

    this.db.run(
      `UPDATE org_members SET role = ? WHERE org_id = ? AND identity_id = ?`,
      [newRole, orgId, identityId],
    );
    this.save();
  }

  /**
   * Remove a member from an organization.
   */
  removeOrgMember(orgId: string, identityId: string): boolean {
    const existing = this.getOrgMember(orgId, identityId);
    if (!existing) return false;
    this.db.run(
      'DELETE FROM org_members WHERE org_id = ? AND identity_id = ?',
      [orgId, identityId],
    );
    this.save();
    return true;
  }

  /**
   * Get an org membership record.
   */
  getOrgMember(orgId: string, identityId: string): OrgMember | null {
    const stmt = this.db.prepare(
      'SELECT * FROM org_members WHERE org_id = ? AND identity_id = ?',
    );
    stmt.bind([orgId, identityId]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as OrgMember;
    }
    stmt.free();
    return null;
  }

  /**
   * List all members of an organization.
   */
  listOrgMembers(orgId: string): (OrgMember & { name: string; type: IdentityType })[] {
    const results: (OrgMember & { name: string; type: IdentityType })[] = [];
    const stmt = this.db.prepare(`
      SELECT om.identity_id, om.org_id, om.role, i.name, i.type
      FROM org_members om
      JOIN identities i ON i.id = om.identity_id
      WHERE om.org_id = ?
      ORDER BY om.role, i.name
    `);
    stmt.bind([orgId]);
    while (stmt.step()) {
      results.push(stmt.getAsObject() as unknown as OrgMember & { name: string; type: IdentityType });
    }
    stmt.free();
    return results;
  }

  /**
   * Get the role of an identity in an org.
   */
  getOrgRole(orgId: string, identityId: string): MemberRole | null {
    const member = this.getOrgMember(orgId, identityId);
    return member?.role ?? null;
  }

  // ─── Project CRUD ───────────────────────────────────────────────

  /**
   * Create a new project within an organization.
   */
  async createProject(orgId: string, name: string, founderIdentityId?: string): Promise<Project> {
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

    const id = await generateId();

    this.db.run(
      `INSERT INTO projects (id, org_id, name) VALUES (?, ?, ?)`,
      [id, orgId, name.trim()],
    );

    if (founderIdentityId) {
      this.db.run(
        `INSERT INTO project_members (identity_id, project_id, role) VALUES (?, ?, 'admin')`,
        [founderIdentityId, id],
      );
    }

    this.save();
    return this.getProject(id)!;
  }

  /**
   * Get a project by ID.
   */
  getProject(id: string): Project | null {
    const stmt = this.db.prepare('SELECT * FROM projects WHERE id = ?');
    stmt.bind([id]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as Project;
    }
    stmt.free();
    return null;
  }

  /**
   * Get a project by name within an org.
   */
  getProjectByName(orgId: string, name: string): Project | null {
    const stmt = this.db.prepare('SELECT * FROM projects WHERE org_id = ? AND name = ?');
    stmt.bind([orgId, name]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as Project;
    }
    stmt.free();
    return null;
  }

  /**
   * List all projects in an organization.
   */
  listProjects(orgId: string): Project[] {
    const results: Project[] = [];
    const stmt = this.db.prepare('SELECT * FROM projects WHERE org_id = ? ORDER BY created_at');
    stmt.bind([orgId]);
    while (stmt.step()) {
      results.push(stmt.getAsObject() as unknown as Project);
    }
    stmt.free();
    return results;
  }

  /**
   * Delete a project by ID.
   */
  deleteProject(id: string): boolean {
    const exists = this.getProject(id);
    if (!exists) return false;
    this.db.run('DELETE FROM projects WHERE id = ?', [id]);
    this.save();
    return true;
  }

  // ─── Project Membership ─────────────────────────────────────────

  /**
   * Add a member to a project with a specified role.
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

    this.db.run(
      `INSERT INTO project_members (identity_id, project_id, role) VALUES (?, ?, ?)`,
      [identityId, projectId, role],
    );
    this.save();
  }

  /**
   * Update a project member's role.
   */
  updateProjectMemberRole(projectId: string, identityId: string, newRole: MemberRole): void {
    if (!VALID_ROLES.includes(newRole)) {
      throw new Error(`Invalid role: '${newRole}'. Must be 'admin', 'member', or 'readonly'`);
    }

    const existing = this.getProjectMember(projectId, identityId);
    if (!existing) {
      throw new Error(`Identity '${identityId}' is not a member of project '${projectId}'`);
    }

    this.db.run(
      `UPDATE project_members SET role = ? WHERE project_id = ? AND identity_id = ?`,
      [newRole, projectId, identityId],
    );
    this.save();
  }

  /**
   * Remove a member from a project.
   */
  removeProjectMember(projectId: string, identityId: string): boolean {
    const existing = this.getProjectMember(projectId, identityId);
    if (!existing) return false;
    this.db.run(
      'DELETE FROM project_members WHERE project_id = ? AND identity_id = ?',
      [projectId, identityId],
    );
    this.save();
    return true;
  }

  /**
   * Get a project membership record.
   */
  getProjectMember(projectId: string, identityId: string): ProjectMember | null {
    const stmt = this.db.prepare(
      'SELECT * FROM project_members WHERE project_id = ? AND identity_id = ?',
    );
    stmt.bind([projectId, identityId]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row as unknown as ProjectMember;
    }
    stmt.free();
    return null;
  }

  /**
   * List all members of a project.
   */
  listProjectMembers(projectId: string): (ProjectMember & { name: string; type: IdentityType })[] {
    const results: (ProjectMember & { name: string; type: IdentityType })[] = [];
    const stmt = this.db.prepare(`
      SELECT pm.identity_id, pm.project_id, pm.role, i.name, i.type
      FROM project_members pm
      JOIN identities i ON i.id = pm.identity_id
      WHERE pm.project_id = ?
      ORDER BY pm.role, i.name
    `);
    stmt.bind([projectId]);
    while (stmt.step()) {
      results.push(stmt.getAsObject() as unknown as ProjectMember & { name: string; type: IdentityType });
    }
    stmt.free();
    return results;
  }

  /**
   * Get the role of an identity in a project.
   */
  getProjectRole(projectId: string, identityId: string): MemberRole | null {
    const member = this.getProjectMember(projectId, identityId);
    return member?.role ?? null;
  }

  // ─── Utility ────────────────────────────────────────────────────

  /**
   * Verify that a private key corresponds to a stored identity.
   */
  async verifyIdentity(privateKeyBase64: string): Promise<Identity | null> {
    try {
      await ensureSodium();
      const secretKey = Buffer.from(privateKeyBase64, 'base64');
      if (secretKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
        return null;
      }

      // Extract the public key from the secret key
      const publicKey = sodium.crypto_sign_ed25519_sk_to_pk(new Uint8Array(secretKey));

      // Hash and look up
      const publicKeyHash = crypto
        .createHash('sha256')
        .update(Buffer.from(publicKey))
        .digest('hex');

      // Check current key
      let identity: Identity | null = null;
      const stmt1 = this.db.prepare('SELECT * FROM identities WHERE public_key_hash = ?');
      stmt1.bind([publicKeyHash]);
      if (stmt1.step()) {
        identity = this.toIdentity(stmt1.getAsObject());
      }
      stmt1.free();

      // Check old key within grace period
      if (!identity) {
        const stmt2 = this.db.prepare(
          'SELECT * FROM identities WHERE old_public_key_hash = ? AND old_key_expires_at IS NOT NULL',
        );
        stmt2.bind([publicKeyHash]);
        if (stmt2.step()) {
          const row = this.toIdentity(stmt2.getAsObject());
          if (row.old_key_expires_at) {
            const expiresAt = new Date(row.old_key_expires_at).getTime();
            if (Date.now() <= expiresAt) {
              identity = row;
            }
          }
        }
        stmt2.free();
      }

      // Zero out the secret key
      sodium.memzero(secretKey);

      return identity;
    } catch {
      return null;
    }
  }

  /**
   * Get the underlying sql.js database. Used by AccessRequestManager.
   */
  getRawDb(): SqlJsDatabase {
    return this.db;
  }

  /**
   * Save pending changes to disk.
   */
  persist(): void {
    this.save();
  }

  /**
   * Close the database connection.
   */
  close(): void {
    try {
      this.save();
    } catch {
      // best effort save on close
    }
    this.db.close();
  }

  // ─── Row mapping ────────────────────────────────────────────────

  private toIdentity(row: Record<string, unknown>): Identity {
    return {
      id: row.id as string,
      name: row.name as string,
      type: row.type as IdentityType,
      public_key_hash: row.public_key_hash as string,
      created_at: row.created_at as string,
      old_public_key_hash: (row.old_public_key_hash as string) ?? null,
      old_key_expires_at: (row.old_key_expires_at as string) ?? null,
    };
  }
}

// ─── Helpers ──────────────────────────────────────────────────────

/**
 * Generate a random ID (16 bytes, hex encoded = 32 chars).
 */
async function generateId(): Promise<string> {
  await ensureSodium();
  const buf = sodium.randombytes_buf(16);
  return Buffer.from(buf).toString('hex');
}

/**
 * Get the default identity database path.
 */
export function getDefaultIdentityDbPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(home, '.hq-vault', 'identity.db');
}
