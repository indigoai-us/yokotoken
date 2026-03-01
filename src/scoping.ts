/**
 * Secret scoping module for hq-vault — US-002.
 *
 * Provides:
 * - Path parsing: extract org/project from scoped paths
 *   e.g. `org/indigo/project/hq-cloud/aws/key` -> { org: 'indigo', project: 'hq-cloud', remainder: 'aws/key' }
 * - Access control checker: given identity memberships and a secret path, determine read/write access
 * - Scope prefix builder for CLI convenience
 *
 * Scoped path format:
 * - Org-scoped:     `org/<org-name>/<remainder>`
 * - Project-scoped: `org/<org-name>/project/<project-name>/<remainder>`
 * - Unscoped:       anything not starting with `org/` (legacy local-only)
 *
 * Access control rules:
 * - Admin in org:     can read/write ALL secrets in that org (including all projects)
 * - Member in org:    can read/write org-level secrets; for project secrets, needs project membership
 * - Readonly in org:  can read org-level secrets but NOT write; for project secrets, needs project membership
 * - Admin in project: can read/write secrets in that project
 * - Member in project: can read/write secrets in that project
 * - Readonly in project: can read but NOT write secrets in that project
 * - Non-member:       no access (403)
 * - Bootstrap token:  bypasses all scope checks (backward compat)
 * - Unscoped secrets: accessible only via bootstrap token
 */

import type { IdentityDatabase, MemberRole } from './identity.js';

// ─── Types ──────────────────────────────────────────────────────────

export interface ParsedScope {
  /** The org name, or null for unscoped paths. */
  org: string | null;
  /** The project name, or null for org-scoped/unscoped paths. */
  project: string | null;
  /** The remainder of the path after the scope prefix. */
  remainder: string;
  /** Whether this is a scoped path (starts with `org/`). */
  scoped: boolean;
}

export type AccessAction = 'read' | 'write';

export interface AccessCheckResult {
  allowed: boolean;
  reason: string;
}

// ─── Path Parsing ────────────────────────────────────────────────────

/**
 * Parse a secret path to extract its scope (org and optional project).
 *
 * Examples:
 * - `org/indigo/aws/key`                        -> { org: 'indigo', project: null, remainder: 'aws/key' }
 * - `org/indigo/project/hq-cloud/aws/key`       -> { org: 'indigo', project: 'hq-cloud', remainder: 'aws/key' }
 * - `org/indigo`                                -> { org: 'indigo', project: null, remainder: '' }
 * - `org/indigo/project/hq-cloud`               -> { org: 'indigo', project: 'hq-cloud', remainder: '' }
 * - `local/my-key`                              -> { org: null, project: null, remainder: 'local/my-key' }
 */
export function parseScope(secretPath: string): ParsedScope {
  // Check if path starts with 'org/'
  if (!secretPath.startsWith('org/')) {
    return {
      org: null,
      project: null,
      remainder: secretPath,
      scoped: false,
    };
  }

  // Extract org name: everything between 'org/' and the next '/' (or end)
  const afterOrg = secretPath.slice(4); // remove 'org/'
  const firstSlash = afterOrg.indexOf('/');

  if (firstSlash === -1) {
    // Path is just `org/<orgName>`
    return {
      org: afterOrg,
      project: null,
      remainder: '',
      scoped: true,
    };
  }

  const orgName = afterOrg.slice(0, firstSlash);
  if (!orgName) {
    // Edge case: `org//something` — invalid but treat as unscoped
    return { org: null, project: null, remainder: secretPath, scoped: false };
  }

  const afterOrgName = afterOrg.slice(firstSlash + 1); // everything after `org/<orgName>/`

  // Check if the next segment is 'project'
  if (afterOrgName.startsWith('project/')) {
    const afterProject = afterOrgName.slice(8); // remove 'project/'
    const projectSlash = afterProject.indexOf('/');

    if (projectSlash === -1) {
      // Path is `org/<orgName>/project/<projectName>`
      return {
        org: orgName,
        project: afterProject || null,
        remainder: '',
        scoped: true,
      };
    }

    const projectName = afterProject.slice(0, projectSlash);
    const remainder = afterProject.slice(projectSlash + 1);

    return {
      org: orgName,
      project: projectName || null,
      remainder,
      scoped: true,
    };
  }

  // No project segment — org-scoped with remainder
  return {
    org: orgName,
    project: null,
    remainder: afterOrgName,
    scoped: true,
  };
}

/**
 * Build a scoped secret path from org, optional project, and a key path.
 *
 * @param org - The organization name
 * @param project - The project name (optional)
 * @param keyPath - The remaining secret path (e.g. 'aws/key')
 * @returns The full scoped path (e.g. 'org/indigo/project/hq-cloud/aws/key')
 */
export function buildScopedPath(org: string, project: string | null, keyPath: string): string {
  if (project) {
    return keyPath ? `org/${org}/project/${project}/${keyPath}` : `org/${org}/project/${project}`;
  }
  return keyPath ? `org/${org}/${keyPath}` : `org/${org}`;
}

// ─── Access Control ──────────────────────────────────────────────────

/**
 * Check if an identity has access to a secret path for a given action.
 *
 * @param identityDb - The identity database to look up memberships
 * @param identityId - The identity requesting access
 * @param secretPath - The secret path being accessed
 * @param action - 'read' or 'write'
 * @returns AccessCheckResult with allowed/denied and reason
 */
export function checkAccess(
  identityDb: IdentityDatabase,
  identityId: string,
  secretPath: string,
  action: AccessAction,
): AccessCheckResult {
  const scope = parseScope(secretPath);

  // Unscoped secrets are only accessible via bootstrap token (caller must handle)
  if (!scope.scoped) {
    return {
      allowed: false,
      reason: 'Unscoped secrets are only accessible via bootstrap token',
    };
  }

  if (!scope.org) {
    return {
      allowed: false,
      reason: 'Invalid scoped path: missing org name',
    };
  }

  // Look up the org by name
  const org = identityDb.getOrgByName(scope.org);
  if (!org) {
    return {
      allowed: false,
      reason: `Org '${scope.org}' not found`,
    };
  }

  // Get the identity's role in the org
  const orgRole = identityDb.getOrgRole(org.id, identityId);

  // If this is a project-scoped secret
  if (scope.project) {
    const project = identityDb.getProjectByName(org.id, scope.project);
    if (!project) {
      return {
        allowed: false,
        reason: `Project '${scope.project}' not found in org '${scope.org}'`,
      };
    }

    // Org admins have full access to all projects in the org
    if (orgRole === 'admin') {
      return {
        allowed: true,
        reason: 'Org admin has full access to all projects',
      };
    }

    // Check project-level membership
    const projectRole = identityDb.getProjectRole(project.id, identityId);

    if (!projectRole && !orgRole) {
      return {
        allowed: false,
        reason: `Identity is not a member of org '${scope.org}' or project '${scope.project}'`,
      };
    }

    if (!projectRole) {
      // Has org membership but not project membership — org members/readonly can't access project secrets
      return {
        allowed: false,
        reason: `Identity is not a member of project '${scope.project}'`,
      };
    }

    // Has project membership — check role vs action
    return checkRoleAccess(projectRole, action, `project '${scope.project}'`);
  }

  // Org-level secret (no project)
  if (!orgRole) {
    return {
      allowed: false,
      reason: `Identity is not a member of org '${scope.org}'`,
    };
  }

  // Check org role vs action
  return checkRoleAccess(orgRole, action, `org '${scope.org}'`);
}

/**
 * Check whether a given role allows the specified action.
 */
function checkRoleAccess(
  role: MemberRole,
  action: AccessAction,
  scopeDesc: string,
): AccessCheckResult {
  if (action === 'read') {
    // All roles can read
    return {
      allowed: true,
      reason: `Role '${role}' in ${scopeDesc} allows read access`,
    };
  }

  // Write access
  if (role === 'readonly') {
    return {
      allowed: false,
      reason: `Role 'readonly' in ${scopeDesc} does not allow write access`,
    };
  }

  return {
    allowed: true,
    reason: `Role '${role}' in ${scopeDesc} allows write access`,
  };
}

/**
 * Filter a list of secret paths to only those the identity can access.
 *
 * Used by the LIST endpoint to return only accessible secrets.
 *
 * @param identityDb - The identity database
 * @param identityId - The identity requesting the list
 * @param paths - The list of secret paths to filter
 * @returns Filtered list of paths the identity can read
 */
export function filterAccessiblePaths(
  identityDb: IdentityDatabase,
  identityId: string,
  paths: string[],
): string[] {
  return paths.filter(p => {
    const result = checkAccess(identityDb, identityId, p, 'read');
    return result.allowed;
  });
}
