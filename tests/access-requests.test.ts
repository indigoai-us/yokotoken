/**
 * Tests for access request and human approval flow — US-004.
 *
 * Covers:
 * - Request creation: valid inputs, validation errors, duplicate rejection
 * - Request polling: get by ID, not found
 * - Approval flow: creates org membership, creates project membership, updates status
 * - Denial flow: updates status, includes reason
 * - Expiry: requests older than 24 hours are treated as expired
 * - Duplicate handling: cannot create a second pending request for same identity/org/project
 * - Server endpoints: POST /v1/access-requests, GET /v1/access-requests/:id
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';

import { IdentityDatabase } from '../src/identity.js';
import { AccessRequestManager, REQUEST_EXPIRY_HOURS } from '../src/access-requests.js';
import { createVaultServer, type ServerConfig } from '../src/server.js';
import { request, type ClientConfig } from '../src/client.js';

// ─── Test Helpers ─────────────────────────────────────────────────

let tmpDir: string;
let db: IdentityDatabase;

async function createTestDb(): Promise<{ db: IdentityDatabase; tmpDir: string }> {
  const td = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-access-req-'));
  const dbPath = path.join(td, 'identity.db');
  const identityDb = await IdentityDatabase.open(dbPath);
  return { db: identityDb, tmpDir: td };
}

function cleanupTestDb(): void {
  if (db) {
    try { db.close(); } catch { /* already closed */ }
  }
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Set up a basic test scenario with an identity, org, and project.
 */
async function setupScenario(identityDb: IdentityDatabase) {
  const identity = await identityDb.createIdentity('test-agent', 'agent');
  const org = await identityDb.createOrg('acme-corp');
  const project = await identityDb.createProject(org.id, 'secret-project', undefined);

  // We need an admin identity for the org to add project members later
  const admin = await identityDb.createIdentity('admin-user', 'human');
  identityDb.addOrgMember(org.id, admin.identity.id, 'admin');

  return { identity, org, project, admin };
}

// ─── Unit Tests: AccessRequestManager ─────────────────────────────

describe('AccessRequestManager — createRequest', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should create a valid access request for an org', async () => {
    const { identity, org } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'Need access to deploy services',
    });

    expect(req.request_id).toBeDefined();
    expect(req.request_id).toHaveLength(32); // 16 bytes hex
    expect(req.identity_id).toBe(identity.identity.id);
    expect(req.org).toBe('acme-corp');
    expect(req.project).toBeNull();
    expect(req.role_requested).toBe('member');
    expect(req.justification).toBe('Need access to deploy services');
    expect(req.status).toBe('pending');
    expect(req.reviewed_by).toBeNull();
    expect(req.reviewed_at).toBeNull();
    expect(req.denial_reason).toBeNull();
    expect(req.created_at).toBeDefined();
  });

  it('should create a valid access request for an org + project', async () => {
    const { identity, org, project } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      project: 'secret-project',
      role_requested: 'readonly',
      justification: 'Need to read config values',
    });

    expect(req.project).toBe('secret-project');
    expect(req.role_requested).toBe('readonly');
    expect(req.status).toBe('pending');
  });

  it('should reject request with non-existent identity', async () => {
    await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.createRequest({
        identity_id: 'nonexistent',
        org: 'acme-corp',
        role_requested: 'member',
        justification: 'test',
      })
    ).toThrow("Identity 'nonexistent' not found");
  });

  it('should reject request with non-existent org', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.createRequest({
        identity_id: identity.identity.id,
        org: 'no-such-org',
        role_requested: 'member',
        justification: 'test',
      })
    ).toThrow("Org 'no-such-org' not found");
  });

  it('should reject request with non-existent project', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.createRequest({
        identity_id: identity.identity.id,
        org: 'acme-corp',
        project: 'no-such-project',
        role_requested: 'member',
        justification: 'test',
      })
    ).toThrow("Project 'no-such-project' not found in org 'acme-corp'");
  });

  it('should reject request with invalid role', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.createRequest({
        identity_id: identity.identity.id,
        org: 'acme-corp',
        role_requested: 'superadmin' as any,
        justification: 'test',
      })
    ).toThrow("Invalid role: 'superadmin'");
  });

  it('should reject request with empty justification', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.createRequest({
        identity_id: identity.identity.id,
        org: 'acme-corp',
        role_requested: 'member',
        justification: '',
      })
    ).toThrow('Justification cannot be empty');
  });

  it('should reject duplicate pending request for same identity/org', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'First request',
    });

    expect(() =>
      arm.createRequest({
        identity_id: identity.identity.id,
        org: 'acme-corp',
        role_requested: 'admin',
        justification: 'Second request',
      })
    ).toThrow('A pending access request already exists');
  });

  it('should allow duplicate after first request is approved', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const first = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'First request',
    });

    arm.approveRequest(first.request_id, 'admin');

    // Now a new pending request should be allowed
    const second = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'admin',
      justification: 'Upgrade to admin',
    });

    expect(second.request_id).toBeDefined();
    expect(second.status).toBe('pending');
  });

  it('should allow duplicate after first request is denied', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const first = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'First request',
    });

    arm.denyRequest(first.request_id, 'admin', 'not now');

    const second = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'Try again',
    });

    expect(second.request_id).toBeDefined();
    expect(second.status).toBe('pending');
  });

  it('should allow different project requests for same org', async () => {
    const { identity, org } = await setupScenario(db);
    // Create a second project
    await db.createProject(org.id, 'other-project', undefined);
    const arm = new AccessRequestManager(db);

    const r1 = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      project: 'secret-project',
      role_requested: 'member',
      justification: 'Need project 1',
    });

    const r2 = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      project: 'other-project',
      role_requested: 'member',
      justification: 'Need project 2',
    });

    expect(r1.request_id).not.toBe(r2.request_id);
  });
});

describe('AccessRequestManager — getRequest', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should retrieve a request by ID', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const created = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    const fetched = arm.getRequest(created.request_id);
    expect(fetched).toBeDefined();
    expect(fetched!.request_id).toBe(created.request_id);
    expect(fetched!.status).toBe('pending');
  });

  it('should return null for non-existent request', async () => {
    await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const result = arm.getRequest('nonexistent');
    expect(result).toBeNull();
  });
});

describe('AccessRequestManager — listRequests', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should list all requests', async () => {
    const { identity } = await setupScenario(db);
    const identity2 = await db.createIdentity('agent-2', 'agent');
    const arm = new AccessRequestManager(db);

    arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'req 1',
    });

    arm.createRequest({
      identity_id: identity2.identity.id,
      org: 'acme-corp',
      role_requested: 'readonly',
      justification: 'req 2',
    });

    const all = arm.listRequests();
    expect(all.length).toBe(2);
  });

  it('should filter by org', async () => {
    const { identity } = await setupScenario(db);
    const org2 = await db.createOrg('other-corp');
    const arm = new AccessRequestManager(db);

    arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'req 1',
    });

    // Create a request for a different org (need a second identity to avoid duplicate detection)
    const identity2 = await db.createIdentity('agent-2', 'agent');
    arm.createRequest({
      identity_id: identity2.identity.id,
      org: 'other-corp',
      role_requested: 'member',
      justification: 'req 2',
    });

    const filtered = arm.listRequests({ org: 'acme-corp' });
    expect(filtered.length).toBe(1);
    expect(filtered[0].org).toBe('acme-corp');
  });

  it('should filter by status', async () => {
    const { identity } = await setupScenario(db);
    const identity2 = await db.createIdentity('agent-2', 'agent');
    const arm = new AccessRequestManager(db);

    const r1 = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'approved one',
    });
    arm.approveRequest(r1.request_id, 'admin');

    arm.createRequest({
      identity_id: identity2.identity.id,
      org: 'acme-corp',
      role_requested: 'readonly',
      justification: 'still pending',
    });

    const pending = arm.listRequests({ status: 'pending' });
    expect(pending.length).toBe(1);
    expect(pending[0].status).toBe('pending');

    const approved = arm.listRequests({ status: 'approved' });
    expect(approved.length).toBe(1);
    expect(approved[0].status).toBe('approved');
  });
});

describe('AccessRequestManager — approveRequest', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should approve a request and create org membership', async () => {
    const { identity, org } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'I need org access',
    });

    const result = arm.approveRequest(req.request_id, 'admin-user');

    expect(result.status).toBe('approved');
    expect(result.reviewed_by).toBe('admin-user');
    expect(result.reviewed_at).toBeDefined();

    // Verify org membership was created
    const orgMember = db.getOrgMember(org.id, identity.identity.id);
    expect(orgMember).toBeDefined();
    expect(orgMember!.role).toBe('member');
  });

  it('should approve a request and create both org and project membership', async () => {
    const { identity, org, project } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      project: 'secret-project',
      role_requested: 'readonly',
      justification: 'Need project read access',
    });

    const result = arm.approveRequest(req.request_id, 'admin-user');

    expect(result.status).toBe('approved');

    // Verify org membership
    const orgMember = db.getOrgMember(org.id, identity.identity.id);
    expect(orgMember).toBeDefined();
    expect(orgMember!.role).toBe('readonly');

    // Verify project membership
    const projectMember = db.getProjectMember(project.id, identity.identity.id);
    expect(projectMember).toBeDefined();
    expect(projectMember!.role).toBe('readonly');
  });

  it('should reject approval of non-existent request', async () => {
    await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.approveRequest('nonexistent', 'admin')
    ).toThrow("Access request 'nonexistent' not found");
  });

  it('should reject approval of already approved request', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    arm.approveRequest(req.request_id, 'admin');

    expect(() =>
      arm.approveRequest(req.request_id, 'admin')
    ).toThrow('is already approved');
  });

  it('should reject approval of already denied request', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    arm.denyRequest(req.request_id, 'admin');

    expect(() =>
      arm.approveRequest(req.request_id, 'admin')
    ).toThrow('is already denied');
  });

  it('should skip org membership creation if already a member', async () => {
    const { identity, org } = await setupScenario(db);
    // Pre-add as org member
    db.addOrgMember(org.id, identity.identity.id, 'readonly');

    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'upgrade',
    });

    // Should not throw — just skips the duplicate membership
    const result = arm.approveRequest(req.request_id, 'admin');
    expect(result.status).toBe('approved');

    // Verify still has original role (not upgraded — idempotent add, not update)
    const orgMember = db.getOrgMember(org.id, identity.identity.id);
    expect(orgMember!.role).toBe('readonly');
  });
});

describe('AccessRequestManager — denyRequest', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should deny a request without reason', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'admin',
      justification: 'I want admin',
    });

    const result = arm.denyRequest(req.request_id, 'admin-user');

    expect(result.status).toBe('denied');
    expect(result.reviewed_by).toBe('admin-user');
    expect(result.reviewed_at).toBeDefined();
    expect(result.denial_reason).toBeNull();
  });

  it('should deny a request with reason', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'admin',
      justification: 'I want admin',
    });

    const result = arm.denyRequest(req.request_id, 'admin-user', 'Admin access not available for agents');

    expect(result.status).toBe('denied');
    expect(result.denial_reason).toBe('Admin access not available for agents');
  });

  it('should reject denial of non-existent request', async () => {
    await setupScenario(db);
    const arm = new AccessRequestManager(db);

    expect(() =>
      arm.denyRequest('nonexistent', 'admin')
    ).toThrow("Access request 'nonexistent' not found");
  });

  it('should reject denial of already processed request', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    arm.denyRequest(req.request_id, 'admin');

    expect(() =>
      arm.denyRequest(req.request_id, 'admin')
    ).toThrow('is already denied');
  });
});

describe('AccessRequestManager — expiry', () => {
  beforeEach(async () => {
    const result = await createTestDb();
    db = result.db;
    tmpDir = result.tmpDir;
  });

  afterEach(() => {
    cleanupTestDb();
  });

  it('should detect expired requests', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    // Manually set created_at to 25 hours ago
    const pastDate = new Date(Date.now() - (REQUEST_EXPIRY_HOURS + 1) * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    // Access the private db to update
    (db as any).db.run(
      'UPDATE access_requests SET created_at = ? WHERE request_id = ?',
      [pastDate, req.request_id],
    );

    const updatedReq = arm.getRequest(req.request_id)!;
    expect(arm.isExpired(updatedReq)).toBe(true);
  });

  it('should not detect fresh requests as expired', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'test',
    });

    expect(arm.isExpired(req)).toBe(false);
  });

  it('should clean expired pending requests', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'will expire',
    });

    // Set to 25 hours ago
    const pastDate = new Date(Date.now() - (REQUEST_EXPIRY_HOURS + 1) * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    (db as any).db.run(
      'UPDATE access_requests SET created_at = ? WHERE request_id = ?',
      [pastDate, req.request_id],
    );

    const cleaned = arm.cleanExpired();
    expect(cleaned).toBe(1);

    const updated = arm.getRequest(req.request_id)!;
    expect(updated.status).toBe('denied');
    expect(updated.denial_reason).toContain('Expired');
  });

  it('should reject approval of expired request', async () => {
    const { identity } = await setupScenario(db);
    const arm = new AccessRequestManager(db);

    const req = arm.createRequest({
      identity_id: identity.identity.id,
      org: 'acme-corp',
      role_requested: 'member',
      justification: 'will expire',
    });

    // Set to 25 hours ago
    const pastDate = new Date(Date.now() - (REQUEST_EXPIRY_HOURS + 1) * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    (db as any).db.run(
      'UPDATE access_requests SET created_at = ? WHERE request_id = ?',
      [pastDate, req.request_id],
    );

    expect(() =>
      arm.approveRequest(req.request_id, 'admin')
    ).toThrow('has expired');
  });
});

// ─── Server Integration Tests ─────────────────────────────────────

describe('Access request server endpoints', () => {
  const TEST_TOKEN = 'test-access-requests-token';

  let serverTmpDir: string;
  let identityTmpDir: string;
  let identityDb: IdentityDatabase;
  let server: http.Server;
  let port: number;
  let clientConfig: ClientConfig;

  beforeAll(async () => {
    // Set up identity database
    identityTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-ar-id-'));
    const identityDbPath = path.join(identityTmpDir, 'identity.db');
    identityDb = await IdentityDatabase.open(identityDbPath);

    // Create test data — all identities must be created before server starts
    // because the server loads its own in-memory copy of the identity DB
    const identity = await identityDb.createIdentity('server-test-agent', 'agent');
    await identityDb.createIdentity('poll-test-agent', 'agent');
    await identityDb.createIdentity('no-auth-agent', 'agent');
    await identityDb.createIdentity('no-auth-poll-agent', 'agent');
    const org = await identityDb.createOrg('test-org');

    // Start test server
    serverTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hq-vault-ar-srv-'));
    const config: ServerConfig = {
      vaultPath: path.join(serverTmpDir, 'vault.db'),
      port: 0,
      idleTimeoutMs: 0,
      pidFile: path.join(serverTmpDir, 'vault.pid'),
      portFile: path.join(serverTmpDir, 'vault.port'),
      tokenFile: path.join(serverTmpDir, 'token'),
      insecure: true,
      token: TEST_TOKEN,
      identityDbPath,
    };

    server = await createVaultServer(config) as http.Server;
    const addr = server.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;

    clientConfig = { port, host: '127.0.0.1', insecure: true };
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    if (identityDb) {
      try { identityDb.close(); } catch { /* ok */ }
    }
    // Small delay to allow SQLite WAL files to be released on Windows
    await new Promise((r) => setTimeout(r, 100));
    try {
      if (serverTmpDir && fs.existsSync(serverTmpDir)) {
        fs.rmSync(serverTmpDir, { recursive: true, force: true });
      }
    } catch { /* Windows EBUSY is non-fatal in tests */ }
    try {
      if (identityTmpDir && fs.existsSync(identityTmpDir)) {
        fs.rmSync(identityTmpDir, { recursive: true, force: true });
      }
    } catch { /* Windows EBUSY is non-fatal in tests */ }
  });

  it('POST /v1/access-requests — should create an access request', async () => {
    const identity = identityDb.getIdentityByName('server-test-agent')!;

    const res = await request(
      clientConfig,
      'POST',
      '/v1/access-requests',
      {
        identity_id: identity.id,
        org: 'test-org',
        role_requested: 'member',
        justification: 'Need access for deployment',
      },
    );

    expect(res.statusCode).toBe(201);
    expect(res.body.request_id).toBeDefined();
    expect(res.body.status).toBe('pending');
  });

  it('POST /v1/access-requests — should reject missing fields', async () => {
    const res = await request(
      clientConfig,
      'POST',
      '/v1/access-requests',
      {
        // Missing identity_id
        org: 'test-org',
        role_requested: 'member',
        justification: 'test',
      },
    );

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('identity_id');
  });

  it('POST /v1/access-requests — should reject invalid org', async () => {
    const identity = identityDb.getIdentityByName('server-test-agent')!;

    const res = await request(
      clientConfig,
      'POST',
      '/v1/access-requests',
      {
        identity_id: identity.id,
        org: 'nonexistent-org',
        role_requested: 'member',
        justification: 'test',
      },
    );

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toContain('not found');
  });

  it('GET /v1/access-requests/:id — should poll request status', async () => {
    // Use pre-created identity (created in beforeAll before server startup)
    const pollIdentity = identityDb.getIdentityByName('poll-test-agent')!;

    const createRes = await request(
      clientConfig,
      'POST',
      '/v1/access-requests',
      {
        identity_id: pollIdentity.id,
        org: 'test-org',
        role_requested: 'readonly',
        justification: 'Polling test',
      },
    );

    expect(createRes.statusCode).toBe(201);
    const requestId = createRes.body.request_id as string;

    // Poll the status
    const pollRes = await request(
      clientConfig,
      'GET',
      `/v1/access-requests/${requestId}`,
    );

    expect(pollRes.statusCode).toBe(200);
    expect(pollRes.body.request_id).toBe(requestId);
    expect(pollRes.body.status).toBe('pending');
    expect(pollRes.body.identity_id).toBe(pollIdentity.id);
    expect(pollRes.body.org).toBe('test-org');
    expect(pollRes.body.justification).toBe('Polling test');
  });

  it('GET /v1/access-requests/:id — should return 404 for non-existent request', async () => {
    const res = await request(
      clientConfig,
      'GET',
      '/v1/access-requests/nonexistent',
    );

    expect(res.statusCode).toBe(404);
    expect(res.body.error).toContain('not found');
  });

  it('POST /v1/access-requests — no auth required', async () => {
    // This test verifies that the endpoint works WITHOUT a Bearer token
    // (agents need this before they have access)
    const noAuthIdentity = identityDb.getIdentityByName('no-auth-agent')!;

    const res = await request(
      { ...clientConfig, token: undefined },
      'POST',
      '/v1/access-requests',
      {
        identity_id: noAuthIdentity.id,
        org: 'test-org',
        role_requested: 'member',
        justification: 'No auth needed for access requests',
      },
    );

    expect(res.statusCode).toBe(201);
    expect(res.body.request_id).toBeDefined();
  });

  it('GET /v1/access-requests/:id — no auth required', async () => {
    const noAuthPollIdentity = identityDb.getIdentityByName('no-auth-poll-agent')!;

    const createRes = await request(
      { ...clientConfig, token: undefined },
      'POST',
      '/v1/access-requests',
      {
        identity_id: noAuthPollIdentity.id,
        org: 'test-org',
        role_requested: 'member',
        justification: 'test',
      },
    );

    const requestId = createRes.body.request_id as string;

    const pollRes = await request(
      { ...clientConfig, token: undefined },
      'GET',
      `/v1/access-requests/${requestId}`,
    );

    expect(pollRes.statusCode).toBe(200);
    expect(pollRes.body.status).toBe('pending');
  });
});
