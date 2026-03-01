/**
 * Access request module for hq-vault — US-004.
 *
 * Provides an access request and human-approval flow:
 * - Agents submit access requests (org/project, role, justification)
 * - Human admins review and approve/deny via CLI
 * - Approved requests automatically create org/project membership
 * - Requests expire after 24 hours if not reviewed
 *
 * Uses the identity database (sql.js) for storage and references
 * the existing identity/org/project tables via foreign keys.
 */

import crypto from 'node:crypto';
import type { Database as SqlJsDatabase } from 'sql.js';
import type { IdentityDatabase, MemberRole } from './identity.js';

// ─── Types ──────────────────────────────────────────────────────────

export type AccessRequestStatus = 'pending' | 'approved' | 'denied';

export interface AccessRequest {
  request_id: string;
  identity_id: string;
  org: string;
  project: string | null;
  role_requested: MemberRole;
  justification: string;
  status: AccessRequestStatus;
  reviewed_by: string | null;
  reviewed_at: string | null;
  denial_reason: string | null;
  created_at: string;
}

export interface AccessRequestCreateInput {
  identity_id: string;
  org: string;
  project?: string | null;
  role_requested: MemberRole;
  justification: string;
}

export interface AccessRequestListFilters {
  org?: string;
  status?: AccessRequestStatus;
}

// ─── Constants ──────────────────────────────────────────────────────

const VALID_ROLES: MemberRole[] = ['admin', 'member', 'readonly'];
const VALID_STATUSES: AccessRequestStatus[] = ['pending', 'approved', 'denied'];

/** Access requests expire after 24 hours if not reviewed. */
export const REQUEST_EXPIRY_HOURS = 24;

// ─── AccessRequestManager ───────────────────────────────────────────

/**
 * Manages access requests within the identity database.
 */
export class AccessRequestManager {
  private identityDb: IdentityDatabase;
  private db: SqlJsDatabase;

  constructor(identityDb: IdentityDatabase) {
    this.identityDb = identityDb;
    this.db = identityDb.getRawDb();
    this.initSchema();
  }

  /**
   * Initialize the access_requests table schema.
   */
  private initSchema(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS access_requests (
        request_id     TEXT PRIMARY KEY,
        identity_id    TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
        org            TEXT NOT NULL,
        project        TEXT,
        role_requested TEXT NOT NULL CHECK(role_requested IN ('admin', 'member', 'readonly')),
        justification  TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied')),
        reviewed_by    TEXT,
        reviewed_at    TEXT,
        denial_reason  TEXT,
        created_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_access_requests_identity_id ON access_requests(identity_id);
      CREATE INDEX IF NOT EXISTS idx_access_requests_org ON access_requests(org);
      CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
    `);

    // Re-enable foreign keys — sql.js multi-statement db.run() can reset PRAGMAs
    this.db.run('PRAGMA foreign_keys = ON');

    this.identityDb.persist();
  }

  // ─── Create ───────────────────────────────────────────────────────

  createRequest(input: AccessRequestCreateInput): AccessRequest {
    const { identity_id, org, project, role_requested, justification } = input;

    // Validate identity exists
    const identity = this.identityDb.getIdentity(identity_id);
    if (!identity) {
      throw new Error(`Identity '${identity_id}' not found`);
    }

    // Validate role
    if (!VALID_ROLES.includes(role_requested)) {
      throw new Error(`Invalid role: '${role_requested}'. Must be 'admin', 'member', or 'readonly'`);
    }

    // Validate justification is non-empty
    if (!justification || justification.trim().length === 0) {
      throw new Error('Justification cannot be empty');
    }

    // Validate org exists (by name)
    const orgRecord = this.identityDb.getOrgByName(org);
    if (!orgRecord) {
      throw new Error(`Org '${org}' not found`);
    }

    // Validate project exists within the org (if specified)
    if (project) {
      const projectRecord = this.identityDb.getProjectByName(orgRecord.id, project);
      if (!projectRecord) {
        throw new Error(`Project '${project}' not found in org '${org}'`);
      }
    }

    // Check for duplicate pending request
    const existingStmt = this.db.prepare(`
      SELECT request_id FROM access_requests
      WHERE identity_id = ? AND org = ? AND (project = ? OR (project IS NULL AND ? IS NULL)) AND status = 'pending'
    `);
    existingStmt.bind([identity_id, org, project ?? null, project ?? null]);
    const hasDuplicate = existingStmt.step();
    existingStmt.free();

    if (hasDuplicate) {
      throw new Error('A pending access request already exists for this identity, org, and project');
    }

    // Generate request ID
    const request_id = crypto.randomBytes(16).toString('hex');

    // Insert the request
    this.db.run(
      `INSERT INTO access_requests (request_id, identity_id, org, project, role_requested, justification)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [request_id, identity_id, org, project ?? null, role_requested, justification.trim()],
    );
    this.identityDb.persist();

    return this.getRequest(request_id)!;
  }

  // ─── Read ─────────────────────────────────────────────────────────

  getRequest(requestId: string): AccessRequest | null {
    const stmt = this.db.prepare('SELECT * FROM access_requests WHERE request_id = ?');
    stmt.bind([requestId]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return this.toAccessRequest(row);
    }
    stmt.free();
    return null;
  }

  listRequests(filters?: AccessRequestListFilters): AccessRequest[] {
    let sql = 'SELECT * FROM access_requests WHERE 1=1';
    const params: unknown[] = [];

    if (filters?.org) {
      sql += ' AND org = ?';
      params.push(filters.org);
    }

    if (filters?.status) {
      if (!VALID_STATUSES.includes(filters.status)) {
        throw new Error(`Invalid status filter: '${filters.status}'. Must be 'pending', 'approved', or 'denied'`);
      }
      sql += ' AND status = ?';
      params.push(filters.status);
    }

    sql += ' ORDER BY created_at DESC';

    const results: AccessRequest[] = [];
    const stmt = this.db.prepare(sql);
    if (params.length > 0) {
      stmt.bind(params as (string | number | null)[]);
    }
    while (stmt.step()) {
      results.push(this.toAccessRequest(stmt.getAsObject()));
    }
    stmt.free();
    return results;
  }

  // ─── Approve ──────────────────────────────────────────────────────

  approveRequest(requestId: string, reviewedBy: string): AccessRequest {
    const request = this.getRequest(requestId);
    if (!request) {
      throw new Error(`Access request '${requestId}' not found`);
    }

    if (request.status !== 'pending') {
      throw new Error(`Access request '${requestId}' is already ${request.status}`);
    }

    // Check if request has expired
    if (this.isExpired(request)) {
      this.db.run(
        `UPDATE access_requests
        SET status = 'denied', denial_reason = 'Expired (not reviewed within 24 hours)', reviewed_at = datetime('now')
        WHERE request_id = ?`,
        [requestId],
      );
      this.identityDb.persist();
      throw new Error(`Access request '${requestId}' has expired`);
    }

    // Resolve the org
    const orgRecord = this.identityDb.getOrgByName(request.org);
    if (!orgRecord) {
      throw new Error(`Org '${request.org}' no longer exists`);
    }

    // Add org membership (skip if already a member)
    const existingOrgMember = this.identityDb.getOrgMember(orgRecord.id, request.identity_id);
    if (!existingOrgMember) {
      this.identityDb.addOrgMember(orgRecord.id, request.identity_id, request.role_requested);
    }

    // Add project membership if requested
    if (request.project) {
      const projectRecord = this.identityDb.getProjectByName(orgRecord.id, request.project);
      if (projectRecord) {
        const existingProjectMember = this.identityDb.getProjectMember(projectRecord.id, request.identity_id);
        if (!existingProjectMember) {
          this.identityDb.addProjectMember(projectRecord.id, request.identity_id, request.role_requested);
        }
      }
    }

    // Update the request status
    this.db.run(
      `UPDATE access_requests
      SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now')
      WHERE request_id = ?`,
      [reviewedBy, requestId],
    );
    this.identityDb.persist();

    return this.getRequest(requestId)!;
  }

  // ─── Deny ─────────────────────────────────────────────────────────

  denyRequest(requestId: string, reviewedBy: string, reason?: string): AccessRequest {
    const request = this.getRequest(requestId);
    if (!request) {
      throw new Error(`Access request '${requestId}' not found`);
    }

    if (request.status !== 'pending') {
      throw new Error(`Access request '${requestId}' is already ${request.status}`);
    }

    this.db.run(
      `UPDATE access_requests
      SET status = 'denied', reviewed_by = ?, reviewed_at = datetime('now'), denial_reason = ?
      WHERE request_id = ?`,
      [reviewedBy, reason?.trim() || null, requestId],
    );
    this.identityDb.persist();

    return this.getRequest(requestId)!;
  }

  // ─── Expiry ───────────────────────────────────────────────────────

  isExpired(request: AccessRequest): boolean {
    const createdAt = new Date(request.created_at + 'Z').getTime();
    const now = Date.now();
    const expiryMs = REQUEST_EXPIRY_HOURS * 60 * 60 * 1000;
    return now - createdAt > expiryMs;
  }

  cleanExpired(): number {
    // Count matching rows first
    const countStmt = this.db.prepare(
      `SELECT COUNT(*) as c FROM access_requests
       WHERE status = 'pending' AND datetime(created_at, '+${REQUEST_EXPIRY_HOURS} hours') < datetime('now')`,
    );
    countStmt.step();
    const count = (countStmt.getAsObject().c as number) || 0;
    countStmt.free();

    if (count > 0) {
      this.db.run(
        `UPDATE access_requests
        SET status = 'denied', denial_reason = 'Expired (not reviewed within 24 hours)', reviewed_at = datetime('now')
        WHERE status = 'pending' AND datetime(created_at, '+${REQUEST_EXPIRY_HOURS} hours') < datetime('now')`,
      );
      this.identityDb.persist();
    }

    return count;
  }

  // ─── Row mapping ────────────────────────────────────────────────

  private toAccessRequest(row: Record<string, unknown>): AccessRequest {
    return {
      request_id: row.request_id as string,
      identity_id: row.identity_id as string,
      org: row.org as string,
      project: (row.project as string) ?? null,
      role_requested: row.role_requested as MemberRole,
      justification: row.justification as string,
      status: row.status as AccessRequestStatus,
      reviewed_by: (row.reviewed_by as string) ?? null,
      reviewed_at: (row.reviewed_at as string) ?? null,
      denial_reason: (row.denial_reason as string) ?? null,
      created_at: row.created_at as string,
    };
  }
}
