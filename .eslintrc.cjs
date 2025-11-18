module.exports = {
  extends: 'airbnb-base',
  globals: {},
  env: {
    node: true,
    browser: true,
    jest: true,
  },
  parserOptions: {
    ecmaVersion: 2023,
  },
  ignorePatterns: ['**/*.min.js'],
  rules: {
    indent: ['error', 2, { MemberExpression: 0 }],
    'no-trailing-spaces': 'error',
    'arrow-parens': 'off',
    'no-plusplus': 'off',
    'class-methods-use-this': 'off',
    'no-await-in-loop': 'off',
    'no-param-reassign': 'off',
    'object-curly-newline': ['error', {
      ObjectExpression: { minProperties: 6, multiline: true, consistent: true },
      ObjectPattern: { minProperties: 6, multiline: true, consistent: true },
      ImportDeclaration: { minProperties: 6, multiline: true, consistent: true },
      ExportDeclaration: { minProperties: 6, multiline: true, consistent: true },
    }],
    'no-restricted-syntax': 'off',
    'import/extensions': 'off',
    'import/no-unresolved': ['error', { ignore: ['^https://'] }],
    'no-restricted-globals': ['error', 'event', 'name', 'location', 'status'],
    'no-bitwise': 'off',
  },
};
