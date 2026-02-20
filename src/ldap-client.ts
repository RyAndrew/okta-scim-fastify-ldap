// ---------------------------------------------------------------------------
// ldapts wrapper
//
// Manages a single bound connection and provides typed helpers for the
// operations the SCIM backend needs.  Every operation is audited to the
// ldap_operations table (fire-and-forget).
// ---------------------------------------------------------------------------

import { Client, Change, Attribute } from 'ldapts';
import type { Knex } from 'knex';
import type { LdapAttributes, LdapUserEntry } from './mapping';

export interface LdapConfig {
  url: string;
  bindDn: string;
  bindPassword: string;
  baseDn: string;
}

// ---------------------------------------------------------------------------

export class LdapClient {
  private client: Client;

  constructor(
    private readonly config: LdapConfig,
    private readonly db: Knex,
  ) {
    this.client = new Client({
      url: config.url,
      // ldapts validates TLS by default; set tlsOptions to customise certs
    });
  }

  async connect(): Promise<void> {
    await this.client.bind(this.config.bindDn, this.config.bindPassword);
  }

  async disconnect(): Promise<void> {
    await this.client.unbind();
  }

  // ── Search ────────────────────────────────────────────────────────────────

  async search(filter: string, attributes?: string[]): Promise<LdapUserEntry[]> {
    const start = Date.now();
    try {
      const { searchEntries } = await this.client.search(this.config.baseDn, {
        filter,
        attributes: attributes ?? ['*', 'entryUUID'],
        scope: 'sub',
      });
      this.audit('search', undefined, { filter }, 0, Date.now() - start);
      return searchEntries as unknown as LdapUserEntry[];
    } catch (err) {
      this.audit('search', undefined, { filter }, 1, Date.now() - start, String(err));
      throw err;
    }
  }

  /** Search for a single entry — returns null if not found. */
  async searchOne(filter: string, attributes?: string[]): Promise<LdapUserEntry | null> {
    const results = await this.search(filter, attributes);
    return results[0] ?? null;
  }

  // ── Add ───────────────────────────────────────────────────────────────────

  async add(dn: string, attrs: LdapAttributes, scimUserId?: string): Promise<void> {
    const start = Date.now();
    const safeAttrs = sanitizeAttrs(attrs);
    try {
      await this.client.add(dn, attrs as Record<string, string | string[]>);
      this.audit('add', dn, safeAttrs, 0, Date.now() - start, undefined, scimUserId);
    } catch (err) {
      this.audit('add', dn, safeAttrs, 1, Date.now() - start, String(err), scimUserId);
      throw err;
    }
  }

  // ── Modify ────────────────────────────────────────────────────────────────

  /**
   * Apply a list of modifications to an entry.
   * Each mod has an attribute name and either a value array (replace/add)
   * or null (delete the attribute entirely).
   */
  async modify(
    dn: string,
    mods: Array<{ attribute: string; value: string[] | null }>,
    scimUserId?: string,
  ): Promise<void> {
    if (mods.length === 0) return;

    const start = Date.now();
    const changes = mods.map(({ attribute, value }) => {
      if (value === null) {
        return new Change({
          operation: 'delete',
          modification: new Attribute({ type: attribute }),
        });
      }
      return new Change({
        operation: 'replace',
        modification: new Attribute({ type: attribute, values: value }),
      });
    });

    const safeAttrs = Object.fromEntries(mods.map((m) => [m.attribute, m.value]));
    try {
      await this.client.modify(dn, changes);
      this.audit('modify', dn, safeAttrs, 0, Date.now() - start, undefined, scimUserId);
    } catch (err) {
      this.audit('modify', dn, safeAttrs, 1, Date.now() - start, String(err), scimUserId);
      throw err;
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  async delete(dn: string, scimUserId?: string): Promise<void> {
    const start = Date.now();
    try {
      await this.client.del(dn);
      this.audit('delete', dn, {}, 0, Date.now() - start, undefined, scimUserId);
    } catch (err) {
      this.audit('delete', dn, {}, 1, Date.now() - start, String(err), scimUserId);
      throw err;
    }
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  private audit(
    operation: string,
    dn: string | undefined,
    attributes: Record<string, unknown>,
    resultCode: number,
    durationMs: number,
    errorMessage?: string,
    scimUserId?: string,
  ): void {
    this.db('ldap_operations')
      .insert({
        operation,
        dn: dn ?? null,
        attributes_json: JSON.stringify(attributes),
        result_code: resultCode,
        error_message: errorMessage ?? null,
        duration_ms: durationMs,
        scim_user_id: scimUserId ?? null,
      })
      .catch((e: Error) => console.error('[ldap-audit] DB write failed:', e.message));
  }
}

// ---------------------------------------------------------------------------

const SENSITIVE_ATTRS = new Set(['userpassword', 'password', 'unicodepwd']);

function sanitizeAttrs(attrs: LdapAttributes): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(attrs)) {
    safe[k] = SENSITIVE_ATTRS.has(k.toLowerCase()) ? '***REDACTED***' : v;
  }
  return safe;
}
