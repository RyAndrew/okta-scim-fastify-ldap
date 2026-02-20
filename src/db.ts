import Knex from 'knex';
import path from 'path';

export const db = Knex({
  client: 'better-sqlite3',
  connection: {
    filename: path.join(__dirname, '..', 'scim-ldap-bridge.db'),
  },
  useNullAsDefault: true,
});

export async function initDb(): Promise<void> {
  // --- incoming_requests ---------------------------------------------------
  if (!(await db.schema.hasTable('incoming_requests'))) {
    await db.schema.createTable('incoming_requests', (t) => {
      t.increments('id').primary();
      t.string('method').notNullable();
      t.text('url').notNullable();
      t.text('query_string').nullable();
      t.string('ip').nullable();
      t.text('request_body').nullable();
      t.integer('response_status').nullable();
      t.text('response_body').nullable();
      t.integer('duration_ms').nullable();
      t.timestamp('created_at').defaultTo(db.fn.now());
    });
  }

  // --- ldap_operations -----------------------------------------------------
  // Audit log for every LDAP operation.
  if (!(await db.schema.hasTable('ldap_operations'))) {
    await db.schema.createTable('ldap_operations', (t) => {
      t.increments('id').primary();
      t.string('operation').notNullable();       // add | modify | delete | search
      t.text('dn').nullable();
      t.text('attributes_json').nullable();       // sanitised — no passwords
      t.integer('result_code').nullable();        // 0 = success
      t.text('error_message').nullable();
      t.integer('duration_ms').nullable();
      t.string('scim_user_id').nullable();
      t.timestamp('created_at').defaultTo(db.fn.now());
    });
  }
}
