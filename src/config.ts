import 'dotenv/config';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export const config = {
  port: Number(process.env.PORT) || 3000,

  ldap: {
    url: requireEnv('LDAP_URL'),
    bindDn: requireEnv('LDAP_BIND_DN'),
    bindPassword: requireEnv('LDAP_BIND_PASSWORD'),
    baseDn: requireEnv('LDAP_BASE_DN'),
    userObjectClass: (
      process.env.LDAP_USER_OBJECT_CLASS ?? 'top,inetOrgPerson,organizationalPerson,person'
    ).split(',').map((s) => s.trim()),
  },

  apiKey: requireEnv('API_KEY'),

  ssl: {
    certPath: requireEnv('SSL_CERT_PATH'),
    keyPath: requireEnv('SSL_KEY_PATH'),
  },
} as const;

export type Config = typeof config;
