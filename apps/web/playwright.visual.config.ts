import { defineConfig } from '@playwright/test';
import baseConfig from './playwright.config';

process.env.EVIDENCESOC_P2_ACCEPTANCE = '1';
process.env.EVIDENCESOC_P3_ACCEPTANCE = '1';
process.env.EVIDENCESOC_P4_ACCEPTANCE = '1';

export default defineConfig({
  ...baseConfig,
  testIgnore: [],
  testMatch: ['**/ui-p2.spec.ts', '**/ui-p3.spec.ts', '**/ui-p4.spec.ts'],
});
