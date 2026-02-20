// ---------------------------------------------------------------------------
// LDAP backend implementation
//
// Implements ScimBackend against any RFC 4519 / inetOrgPerson-compatible
// LDAP directory (OpenLDAP, 389 Directory Server, etc.).
//
// User identity: entryUUID (RFC 4530) is used as the SCIM id.
// Active/disabled: pwdAccountLockedTime (LDAP Password Policy, RFC 3112).
// ---------------------------------------------------------------------------

import {
  ScimBackend,
  ScimBackendError,
  ScimUser,
  ScimPatchOp,
  ListUsersOptions,
  ListUsersResult,
  applyPatchOps,
} from 'scim-fastify-core';
import { LdapClient } from './ldap-client';
import {
  scimToLdapAttrs,
  scimToLdapModifications,
  ldapEntryToScimUser,
  LdapUserEntry,
} from './mapping';

// ---------------------------------------------------------------------------
// SCIM attribute → LDAP filter map for listUsers
// ---------------------------------------------------------------------------

const SCIM_ATTR_TO_LDAP: Record<string, string> = {
  id: 'entryUUID',
  externalid: 'employeeNumber',
  username: 'uid',
};

// ---------------------------------------------------------------------------

export class LdapBackend implements ScimBackend {
  constructor(
    private readonly ldap: LdapClient,
    private readonly config: {
      ldap: { baseDn: string; userObjectClass: readonly string[] };
    },
  ) {}

  // ── List ────────────────────────────────────────────────────────────────

  async listUsers({ filter, startIndex, count }: ListUsersOptions): Promise<ListUsersResult> {
    const baseFilter = `(objectClass=${this.config.ldap.userObjectClass.find((c) => c !== 'top') ?? 'inetOrgPerson'})`;

    let ldapFilter = baseFilter;
    if (filter && filter.operator === 'eq') {
      const ldapAttr = SCIM_ATTR_TO_LDAP[filter.attribute.toLowerCase()];
      if (ldapAttr) {
        ldapFilter = `(&${baseFilter}(${ldapAttr}=${escapeLdap(filter.value)}))`;
      }
    }

    const entries = await this.ldap.search(ldapFilter);
    const users = entries.map(ldapEntryToScimUser);

    // Client-side pagination (LDAP doesn't expose SQL-style OFFSET/LIMIT)
    const total = users.length;
    const page = users.slice(startIndex - 1, startIndex - 1 + count);

    return { users: page, totalResults: total };
  }

  // ── Get ─────────────────────────────────────────────────────────────────

  async getUser(id: string): Promise<ScimUser> {
    const entry = await this.ldap.searchOne(
      `(entryUUID=${escapeLdap(id)})`,
    );
    if (!entry) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }
    return ldapEntryToScimUser(entry);
  }

  // ── Create ───────────────────────────────────────────────────────────────

  async createUser(user: ScimUser): Promise<ScimUser> {
    // Check for duplicate uid
    const uid = user.userName.split('@')[0];
    const existing = await this.ldap.searchOne(`(uid=${escapeLdap(uid)})`);
    if (existing) {
      throw new ScimBackendError(
        409,
        `A user with userName '${user.userName}' already exists.`,
        'uniqueness',
      );
    }

    const dn = this.buildDn(uid);
    const attrs = scimToLdapAttrs(user);
    attrs['objectClass'] = [...this.config.ldap.userObjectClass];

    // Use externalId as employeeNumber if provided
    if (user.externalId) {
      attrs['employeeNumber'] = user.externalId;
    }

    // Set a placeholder password so the account can bind; real password
    // management is out of SCIM scope — set via separate workflow.
    // Some LDAP servers require a userPassword on add — omit if yours doesn't.
    // attrs['userPassword'] = '{SSHA}...';

    try {
      await this.ldap.add(dn, attrs, user.externalId);
    } catch (err) {
      throw mapLdapError(err);
    }

    // Read back to get the server-assigned entryUUID
    const created = await this.ldap.searchOne(`(uid=${escapeLdap(uid)})`);
    if (!created) {
      // Extremely unlikely — just return a synthesised response
      return { ...user, id: crypto.randomUUID() };
    }
    return ldapEntryToScimUser(created);
  }

  // ── Replace ──────────────────────────────────────────────────────────────

  async replaceUser(id: string, user: ScimUser): Promise<ScimUser> {
    const entry = await this.requireEntry(id);
    const mods = scimToLdapModifications(user);

    try {
      await this.ldap.modify(entry.dn, mods, id);
    } catch (err) {
      throw mapLdapError(err);
    }

    return ldapEntryToScimUser(await this.requireEntry(id));
  }

  // ── Patch ────────────────────────────────────────────────────────────────

  async patchUser(id: string, patch: ScimPatchOp): Promise<ScimUser> {
    const entry = await this.requireEntry(id);
    const current = ldapEntryToScimUser(entry) as unknown as Record<string, unknown>;

    const { updated } = applyPatchOps(current, patch.Operations);
    const partial = updated as Partial<ScimUser>;
    const mods = scimToLdapModifications(partial);

    try {
      await this.ldap.modify(entry.dn, mods, id);
    } catch (err) {
      throw mapLdapError(err);
    }

    return ldapEntryToScimUser(await this.requireEntry(id));
  }

  // ── Delete ───────────────────────────────────────────────────────────────

  async deleteUser(id: string): Promise<void> {
    const entry = await this.ldap.searchOne(`(entryUUID=${escapeLdap(id)})`);
    if (!entry) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }

    try {
      await this.ldap.delete(entry.dn, id);
    } catch (err) {
      throw mapLdapError(err);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  private buildDn(uid: string): string {
    return `uid=${escapeDn(uid)},${this.config.ldap.baseDn}`;
  }

  private async requireEntry(id: string): Promise<LdapUserEntry> {
    const entry = await this.ldap.searchOne(`(entryUUID=${escapeLdap(id)})`);
    if (!entry) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }
    return entry;
  }
}

// ---------------------------------------------------------------------------
// LDAP error → ScimBackendError
// ---------------------------------------------------------------------------

function mapLdapError(err: unknown): ScimBackendError {
  const msg = String(err).toLowerCase();

  if (msg.includes('already exists') || msg.includes('entry already exists') || msg.includes('68')) {
    return new ScimBackendError(409, String(err), 'uniqueness');
  }
  if (msg.includes('no such object') || msg.includes('32') || msg.includes('not found')) {
    return new ScimBackendError(404, String(err), 'noTarget');
  }
  if (msg.includes('insufficient access') || msg.includes('50')) {
    return new ScimBackendError(403, String(err));
  }
  if (msg.includes('invalid') || msg.includes('constraint') || msg.includes('19')) {
    return new ScimBackendError(400, String(err), 'invalidValue');
  }

  return new ScimBackendError(500, String(err));
}

// ---------------------------------------------------------------------------
// LDAP injection escaping
// ---------------------------------------------------------------------------

/** Escape a value for use in an LDAP search filter (RFC 4515). */
function escapeLdap(value: string): string {
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

/** Escape a value for use in a DN attribute value (RFC 4514). */
function escapeDn(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/,/g, '\\,')
    .replace(/\+/g, '\\+')
    .replace(/"/g, '\\"')
    .replace(/</g, '\\<')
    .replace(/>/g, '\\>')
    .replace(/;/g, '\\;')
    .replace(/^[ #]/, (c) => '\\' + c)
    .replace(/[ ]$/, '\\ ');
}
