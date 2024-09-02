module.exports = {
  root: true,
  ignorePatterns: ['./.eslint.cjs', '**/vite.config.ts'],
  extends: [
    'eslint:recommended',
    'plugin:prettier/recommended',
    "plugin:import/recommended",
    "plugin:import/typescript",
    'plugin:react/recommended', // Uses the recommended rules from @eslint-plugin-react
    'plugin:react/jsx-runtime',
    'plugin:@typescript-eslint/eslint-recommended', // Uses the recommended rules from the @typescript-eslint/eslint-plugin
    'plugin:@typescript-eslint/recommended', // Uses the recommended rules from the @typescript-eslint/eslint-plugin
    'prettier', // Uses eslint-config-prettier to disable ESLint rules from @typescript-eslint/eslint-plugin that would conflict with prettier
    'plugin:jsx-a11y/recommended',
  ],
  parser: '@typescript-eslint/parser', // Specifies the ESLint parser
  env: {
    browser: true,
    es6: true,
    node: true,
  },
  parserOptions: {
    ecmaVersion: 2020, // Allows for the parsing of modern ECMAScript features
    sourceType: 'module', // Allows for the use of imports
    ecmaFeatures: {
      jsx: true, // Allows for the parsing of JSX
      arrowFunctions: true,
    },
    // Next two lines enable deeper TS type checking
    // https://typescript-eslint.io/docs/linting/typed-linting/
    tsconfigRootDir: __dirname,
    project: [
      'lib/tsconfig.json',
      'cli/tsconfig.json',
      'react/tsconfig.json',
      'data-browser/tsconfig.json',
      'e2e/tsconfig.json',
      'create-template/tsconfig.json',
    ],
  },
  plugins: ['react', '@typescript-eslint', 'prettier', 'react-hooks', 'jsx-a11y'],
  settings: {
    react: {
      version: 'detect', // Tells eslint-plugin-react to automatically detect the version of React to use
    },
    'import/resolver': {
      node: {
        extensions: ['.js', '.jsx', '.ts', '.tsx'],
        paths: ['./src'],
      },
    },
  },
  rules: {
    // Existing rules
    'comma-dangle': 'off', // https://eslint.org/docs/rules/comma-dangle
    'function-paren-newline': 'off', // https://eslint.org/docs/rules/function-paren-newline
    'global-require': 'off', // https://eslint.org/docs/rules/global-require
    // Turn this on when we have migrated all import paths to use `.js`
    // "import/extensions": ["error", "ignorePackages"],
    "import/no-unresolved": "off",
    'import/no-dynamic-require': 'off', // https://github.com/benmosher/eslint-plugin-import/blob/master/docs/rules/no-dynamic-require.md
    'import/no-named-as-default': 'off',
    'no-inner-declarations': 'off', // https://eslint.org/docs/rules/no-inner-declarations// New rules
    'class-methods-use-this': 'off',
    //Allow underscores https://stackoverflow.com/questions/57802057/eslint-configuring-no-unused-vars-for-typescript
    '@typescript-eslint/no-unused-vars': ['error', { 'varsIgnorePattern': '^_', 'argsIgnorePattern': '^_' }],
    'react-hooks/exhaustive-deps': 'off',
    // 'no-unused-vars': ["error", { "ie": "^_" }],
    'import/prefer-default-export': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-var-requires': 'off',
    '@typescript-eslint/ban-ts-comment': 'off',
    '@typescript-eslint/no-explicit-any': 'error',
    "react-hooks/rules-of-hooks": "error", // Checks rules of Hooks
    'no-console': ['error', { allow: ['error', 'warn'] }],
    "react/prop-types": "off",
    "padding-line-between-statements": [
      "error",
      {
        "blankLine": "always",
        "next": "return",
        "prev": "*"
      },
      {
        "blankLine": "always",
        "next": "export",
        "prev": "*"
      },
      {
        "blankLine": "always",
        "next": "multiline-block-like",
        "prev": "*"
      },
      {
        "blankLine": "always",
        "next": "*",
        "prev": "multiline-block-like"
      },
      {
        "blankLine": "any",
        "next": "export",
        "prev": "export"
      }
    ],
    "@typescript-eslint/explicit-member-accessibility": "error",
    "eqeqeq": "error",
    "no-unused-expressions": ["error", { "allowShortCircuit": true, "allowTaggedTemplates": true }],
    "jsx-a11y/no-autofocus": "off",
    // This has a bug, so we use typescripts version
    "no-shadow": "off",
    "@typescript-eslint/no-non-null-assertion": "off",
    "no-eval": "error",
    "no-implied-eval": "error",
    "@typescript-eslint/no-shadow": ["error"],
    "@typescript-eslint/member-ordering": "error",
    "react/no-unknown-property": ["error", { "ignore": ["about"] }],
  },
};
