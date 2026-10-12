import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globalSetup: ['./test/global-setup.ts'],
        env: {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgres://umoja:umoja@localhost:5432/umoja_test',
      AUDIT_HASH_KEY:
        '0000000000000000000000000000000000000000000000000000000000000000',
      SERVER_ID: 'umoja-backend-test',
      LOG_LEVEL: 'error',
      WS_REVALIDATE_SECONDS: '2',
      WS_HEARTBEAT_SECONDS: '2',
      WS_AUTH_TIMEOUT_SECONDS: '2',
    },
    testTimeout: 15000,
    hookTimeout: 30000,
  },
});
