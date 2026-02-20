// ---------------------------------------------------------------------------
// SCIM 2.0 ↔ LDAP attribute mapping
//
// RFC 4530 entryUUID is used as the SCIM id — it is assigned by the LDAP
// server and returned in search results.
//
// The `active` field maps to `pwdAccountLockedTime` (LDAP Password Policy,
// RFC 3112).  Setting it to '000001010000Z' permanently locks the account
// (disabled); deleting the attribute re-enables it.  This attribute may not
// exist on all LDAP servers — see your server's docs for alternatives.
// ---------------------------------------------------------------------------

import { ScimUser } from 'scim-fastify-core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** LDAP attribute bag — values are always string arrays in ldapts. */
export type LdapAttributes = Record<string, string | string[]>;

export interface LdapUserEntry {
  dn: string;
  entryUUID?: string;
  uid?: string;
  cn?: string;
  givenName?: string;
  sn?: string;
  mail?: string;
  displayName?: string;
  pwdAccountLockedTime?: string;
  employeeNumber?: string;
  [key: string]: string | string[] | undefined;
}

// LDAP permanently-locked timestamp (effectively disables the account)
const LOCKED_TIME = '000001010000Z';

// ---------------------------------------------------------------------------
// SCIM → LDAP
// ---------------------------------------------------------------------------

/**
 * Converts a SCIM User resource to an LDAP attribute bag for `add` operations.
 * The `objectClass` array must be appended by the caller.
 */
export function scimToLdapAttrs(user: ScimUser): LdapAttributes {
  const attrs: LdapAttributes = {};

  // uid (required by inetOrgPerson)
  const uid = user.userName.split('@')[0];
  attrs['uid'] = uid;

  // cn (required by person) — prefer displayName, fall back to uid
  attrs['cn'] = user.displayName ?? uid;

  // sn (required by person) — fall back to uid when family name is absent
  if (user.name?.familyName) {
    attrs['sn'] = user.name.familyName;
  } else {
    attrs['sn'] = uid;
  }

  if (user.name?.givenName) attrs['givenName'] = user.name.givenName;
  if (user.displayName) attrs['displayName'] = user.displayName;
  if (user.externalId) attrs['employeeNumber'] = user.externalId;

  const primaryEmail = user.emails?.find((e) => e.primary) ?? user.emails?.[0];
  if (primaryEmail?.value) attrs['mail'] = primaryEmail.value;

  if (user.active === false) {
    attrs['pwdAccountLockedTime'] = LOCKED_TIME;
  }

  return attrs;
}

/**
 * Returns LDAP Change objects (as plain objects) for a replace/patch operation.
 * Only the fields present in `partial` are included.
 */
export function scimToLdapModifications(
  partial: Partial<ScimUser>,
): Array<{ attribute: string; value: string[] | null }> {
  const mods: Array<{ attribute: string; value: string[] | null }> = [];

  const set = (attr: string, value: string | undefined | null) => {
    if (value !== undefined) {
      mods.push({ attribute: attr, value: value === null ? null : [value] });
    }
  };

  if (partial.userName !== undefined) {
    set('uid', partial.userName.split('@')[0]);
  }
  if (partial.displayName !== undefined) {
    set('displayName', partial.displayName ?? null);
    set('cn', partial.displayName ?? partial.userName?.split('@')[0] ?? null);
  }
  if (partial.name?.givenName !== undefined) {
    set('givenName', partial.name.givenName ?? null);
  }
  if (partial.name?.familyName !== undefined) {
    set('sn', partial.name.familyName ?? null);
  }
  if (partial.externalId !== undefined) {
    set('employeeNumber', partial.externalId ?? null);
  }

  const primaryEmail = partial.emails?.find((e) => e.primary) ?? partial.emails?.[0];
  if (primaryEmail !== undefined) {
    set('mail', primaryEmail?.value ?? null);
  }

  if (typeof partial.active === 'boolean') {
    mods.push({
      attribute: 'pwdAccountLockedTime',
      value: partial.active ? null : [LOCKED_TIME],
    });
  }

  return mods;
}

// ---------------------------------------------------------------------------
// LDAP → SCIM
// ---------------------------------------------------------------------------

/**
 * Converts an LDAP entry (from ldapts search results) to a SCIM User.
 * `meta.location` is NOT set here — the route factory adds it via `withScimMeta`.
 */
export function ldapEntryToScimUser(entry: LdapUserEntry): ScimUser {
  const id = firstString(entry['entryUUID']) ?? entry.dn;
  const userName =
    firstString(entry['uid']) ??
    entry.dn.split(',')[0]?.replace(/^uid=/i, '') ??
    id;

  const givenName = firstString(entry['givenName']);
  const familyName = firstString(entry['sn']);
  const hasName = Boolean(givenName ?? familyName);

  const lockedTime = firstString(entry['pwdAccountLockedTime']);
  const active = lockedTime !== LOCKED_TIME;

  const mail = firstString(entry['mail']);

  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id,
    externalId: firstString(entry['employeeNumber']) ?? undefined,
    userName,
    displayName: firstString(entry['displayName']) ?? undefined,
    ...(hasName
      ? {
          name: {
            ...(givenName ? { givenName } : {}),
            ...(familyName ? { familyName } : {}),
          },
        }
      : {}),
    ...(mail ? { emails: [{ value: mail, type: 'work', primary: true }] } : {}),
    active,
    meta: {
      resourceType: 'User',
    },
  };
}

// ---------------------------------------------------------------------------

function firstString(v: string | string[] | undefined): string | undefined {
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v[0] : v;
}
