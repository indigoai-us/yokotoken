export { VaultEngine } from './vault.js';
export type { SecretEntry, SecretMetadata, SecretListEntry, VaultStatus } from './vault.js';
export {
  createVaultServer,
  getDefaultVaultPath,
  getDefaultPidFile,
  getDefaultPortFile,
  getVaultDir,
  isServerRunning,
  readServerPort,
  DEFAULT_PORT,
  DEFAULT_IDLE_TIMEOUT_MS,
} from './server.js';
export type { ServerConfig } from './server.js';
export { request as vaultRequest } from './client.js';
export type { ClientConfig, ClientResponse } from './client.js';
export { readPassphrase, readAndConfirmPassphrase } from './passphrase.js';
export {
  generateToken,
  getDefaultTokenFile,
  writeTokenFile,
  readTokenFile,
  validateBearerToken,
  RateLimiter,
  DEFAULT_RATE_LIMIT,
} from './auth.js';
export type { RateLimitConfig } from './auth.js';
export {
  ensureCerts,
  generateSelfSignedCert,
  getDefaultCertPaths,
  certsExist,
} from './tls.js';
export type { TlsCertPaths, TlsCertData } from './tls.js';
export {
  TokenManager,
  generateAccessToken,
  hashToken,
  parseTTL,
} from './tokens.js';
export type {
  TokenCreateOptions,
  TokenCreateResult,
  TokenMetadata,
  TokenValidationResult,
} from './tokens.js';
export {
  getSecret,
  storeSecret,
  listSecrets,
  VaultSdkError,
} from './sdk.js';
export type {
  SecretEntry as SdkSecretEntry,
  SecretMetadata as SdkSecretMetadata,
  VaultSdkConfig,
} from './sdk.js';
export {
  startDaemon,
  stopDaemon,
  restartDaemon,
  rotateLogIfNeeded,
  getDefaultLogFile,
  MAX_LOG_SIZE,
} from './daemon.js';
export type {
  DaemonStartOptions,
  DaemonStartResult,
  DaemonStopResult,
} from './daemon.js';
export {
  AuditLogger,
  readAuditLog,
  tailAuditLog,
  getDefaultAuditLogPath,
} from './audit.js';
export type {
  AuditOperation,
  AuditEntry,
  AuditFilterOptions,
} from './audit.js';
export {
  createBackup,
  restoreBackup,
  exportEnv,
  importEnv,
  parseEnvFile,
  pathToEnvName,
  envNameToPath,
  detectImportDuplicates,
  BACKUP_MAGIC,
  BACKUP_VERSION,
  BACKUP_HEADER_SIZE,
} from './backup.js';
export type {
  BackupResult,
  RestoreResult,
  ExportResult,
  ImportResult,
  ImportConflictStrategy,
  ImportDuplicate,
  EnvEntry,
} from './backup.js';
export {
  IdentityDatabase,
  getDefaultIdentityDbPath,
} from './identity.js';
export type {
  Identity,
  IdentityType,
  Org,
  Project,
  OrgMember,
  ProjectMember,
  MemberRole,
  IdentityCreateResult,
} from './identity.js';
