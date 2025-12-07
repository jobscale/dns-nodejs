import jestPlugin from 'eslint-plugin-jest';
import standard from '@jobscale/eslint-plugin-standard';

export default [{
  ignores: [
    ...standard.configs.standard.ignores,
  ],
}, {
  ...standard.configs.node,
  name: 'node rule',
  files: ['**/*.js'],
  rules: {
    ...standard.rules,
  },
}, {
  ...standard.configs.browser,
  name: 'browser rule',
  files: ['docs/**/*.js', 'public/**/*.js', 'src/**/*.js'],
  rules: {
    ...standard.rules,
  },
}, {
  ...standard.configs.jest,
  name: 'jest rule',
  files: ['**/*.test.js', '**/__tests__/**/*.js'],
  plugins: {
    jest: jestPlugin,
  },
  rules: {
    ...standard.rules,
    ...jestPlugin.configs.recommended.rules,
    'jest/no-disabled-tests': 'warn',
    'jest/no-focused-tests': 'error',
    'jest/no-identical-title': 'error',
    'jest/prefer-to-have-length': 'warn',
    'jest/valid-expect': 'error',
  },
}];
