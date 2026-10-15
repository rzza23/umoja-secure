import { describe, it, expect } from 'vitest';
import { deviceIdSchema } from './deviceId.js';

describe('deviceIdSchema', () => {
  describe('accepts canonical hyphenated UUIDs', () => {
    it('accepts a v4 UUID', () => {
      expect(deviceIdSchema.safeParse('123e4567-e89b-42d3-a456-426614174000').success).toBe(true);
    });

    it('accepts a v1 UUID', () => {
      expect(deviceIdSchema.safeParse('f47ac10b-58cc-1372-a567-0e02b2c3d479').success).toBe(true);
    });

    it('accepts a v7 UUID', () => {
      expect(deviceIdSchema.safeParse('017f22e2-79b0-7cc3-98c4-dc0c0c07398f').success).toBe(true);
    });

    it('accepts the nil UUID', () => {
      expect(deviceIdSchema.safeParse('00000000-0000-0000-0000-000000000000').success).toBe(true);
    });

    it('accepts uppercase hex', () => {
      expect(deviceIdSchema.safeParse('123E4567-E89B-42D3-A456-426614174000').success).toBe(true);
    });
  });

  describe('rejects non-canonical or malformed strings', () => {
    it('rejects a non-UUID label', () => {
      expect(deviceIdSchema.safeParse('device-007').success).toBe(false);
    });

    it('rejects an empty string', () => {
      expect(deviceIdSchema.safeParse('').success).toBe(false);
    });

    it('rejects an over-length string', () => {
      expect(deviceIdSchema.safeParse('123e4567-e89b-42d3-a456-426614174000-extra').success).toBe(false);
    });

    it('rejects embedded whitespace', () => {
      expect(deviceIdSchema.safeParse('123e4567-e89b-42d3-a456-4266 4174000').success).toBe(false);
    });

    it('rejects non-hex characters', () => {
      expect(deviceIdSchema.safeParse('123g4567-e89b-42d3-a456-426614174000').success).toBe(false);
    });

    it('rejects a UUID wrapped in braces', () => {
      expect(deviceIdSchema.safeParse('{123e4567-e89b-42d3-a456-426614174000}').success).toBe(false);
    });

    it('rejects a UUID without hyphens', () => {
      expect(deviceIdSchema.safeParse('123e4567e89b42d3a456426614174000').success).toBe(false);
    });
  });
});
