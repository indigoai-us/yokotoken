/**
 * Access request module for hq-vault — US-004.
 *
 * Provides an access request and human-approval flow:
 * - Agents submit access requests (org/project, role, justification)
 * - Human admins review and approve/deny via CLI
 * - Approved requests automatically create org/project membership
 * - Requests expire after 24 hours if not reviewed
 *
 * Uses the identity database (SQLite) for storage and references
 * the existing identity/org/project tables via foreign keys.
 */

import crypto from 'node:crypto';
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
 *
 * Creates an `access_requests` table in the identity database
 * and provides CRUD + approval/denial operations.
 */
export class AccessRequestManager {
  private identityDb: IdentityDatabase;
  private db: ReturnType<typeof this.getDb>;

  constructor(identityDb: IdentityDatabase) {
    this.identityDb = identityDb;
    this.db = this.getDb();
    this.initSchema();
  }

  /**
   * Access the underlying better-sqlite3 database from the IdentityDatabase.
   * We use the same database connection to ensure foreign key consistency.
   */
  private getDb() {
    // Access the private db property — we need to use the same SQLite connection
    // as the IdentityDatabase for foreign key enforcement.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (this.identityDb as any).db;
  }

  /**
   * Initialize the access_requests table schema.
   */
  private initSchema(): void {
    this.db.exec(`
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
  }

  // ─── Create ───────────────────────────────────────────────────────

  /**
   * Create a new access request.
   *
   * Validates:
   * - Identity must exist
   * - Org must exist (by name)
   * - If project is specified, it must exist within the org
   * - Role must be valid
   * - No duplicate pending request for the same identity/org/project
   *
   * @returns The created access request with request_id and status 'pending'.
   */
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
    const existing = existingStmt.get(identity_id, org, project ?? null, project ?? null);
    if (existing) {
      throw new Error('A pending access request already exists for this identity, org, and project');
    }

    // Generate request ID
    const request_id = crypto.randomBytes(16).toString('hex');

    // Insert the request
    this.db.prepare(`
      INSERT INTO access_requests (request_id, identity_id, org, project, role_requested, justification)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(request_id, identity_id, org, project ?? null, role_requested, justification.trim());

    return this.getRequest(request_id)!;
  }

  // ─── Read ─────────────────────────────────────────────────────────

  /**
   * Get an access request by ID.
   */
  getRequest(requestId: string): AccessRequest | null {
    const row = this.db.prepare(
      'SELECT * FROM access_requests WHERE request_id = ?'
    ).get(requestId) as AccessRequest | undefined;
    return row ?? null;
  }

  /**
   * List access requests with optional filters.
   *
   * @param filters - Optional filters: org (name), status.
   * @returns Array of matching access requests, ordered by created_at DESC.
   */
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

    return this.db.prepare(sql).all(...params) as AccessRequest[];
  }

  // ─── Approve ──────────────────────────────────────────────────────

  /**
   * Approve an access request.
   *
   * - Updates the request status to 'approved'
   * - Creates the org membership (and project membership if specified)
   * - Uses the requested role
   *
   * @param requestId - The request ID to approve.
   * @param reviewedBy - The identity/name of the reviewer.
   * @returns The updated access request.
   */
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
      // Mark as denied due to expiry
      this.db.prepare(`
        UPDATE access_requests
        SET status = 'denied', denial_reason = 'Expired (not reviewed within 24 hours)', reviewed_at = datetime('now')
        WHERE request_id = ?
      `).run(requestId);
      throw new Error(`Access request '${requestId}' has expired`);
    }

    // Resolve the org
    const orgRecord = this.identityDb.getOrgByName(request.org);
    if (!orgRecord) {
      throw new Error(`Org '${request.org}' no longer exists`);
    }

    // Create memberships in a transaction
    const updateStatus = this.db.prepare(`
      UPDATE access_requests
      SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now')
      WHERE request_id = ?
    `);

    const transaction = this.db.transaction(() => {
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
      updateStatus.run(reviewedBy, requestId);
    });

    transaction();

    return this.getRequest(requestId)!;
  }

  // ─── Deny ─────────────────────────────────────────────────────────

  /**
   * Deny an access request.
   *
   * @param requestId - The request ID to deny.
   * @param reviewedBy - The identity/name of the reviewer.
   * @param reason - Optional denial reason.
   * @returns The updated access request.
   */
  denyRequest(requestId: string, reviewedBy: string, reason?: string): AccessRequest {
    const request = this.getRequest(requestId);
    if (!request) {
      throw new Error(`Access request '${requestId}' not found`);
    }

    if (request.status !== 'pending') {
      throw new Error(`Access request '${requestId}' is already ${request.status}`);
    }

    this.db.prepare(`
      UPDATE access_requests
      SET status = 'denied', reviewed_by = ?, reviewed_at = datetime('now'), denial_reason = ?
      WHERE request_id = ?
    `).run(reviewedBy, reason?.trim() || null, requestId);

    return this.getRequest(requestId)!;
  }

  // ─── Expiry ───────────────────────────────────────────────────────

  /**
   * Check if an access request has expired (older than 24 hours).
   */
  isExpired(request: AccessRequest): boolean {
    const createdAt = new Date(request.created_at + 'Z').getTime();
    const now = Date.now();
    const expiryMs = REQUEST_EXPIRY_HOURS * 60 * 60 * 1000;
    return now - createdAt > expiryMs;
  }

  /**
   * Clean up expired pending requests by marking them as denied.
   *
   * @returns The number of requests expired.
   */
  cleanExpired(): number {
    const result = this.db.prepare(`
      UPDATE access_requests
      SET status = 'denied', denial_reason = 'Expired (not reviewed within 24 hours)', reviewed_at = datetime('now')
      WHERE status = 'pending' AND datetime(created_at, '+${REQUEST_EXPIRY_HOURS} hours') < datetime('now')
    `).run();

    return result.changes;
  }
}
