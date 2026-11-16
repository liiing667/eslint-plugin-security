'use strict';

const RuleTester = require('eslint').RuleTester;

const tester = new RuleTester({ languageOptions: { sourceType: 'commonjs' } });

const ruleName = 'detect-non-literal-require';

tester.run(ruleName, require(`../../rules/${ruleName}`), {
  valid: [
    { code: "var a = require('b')" },
    { code: 'var a = require(`b`)' },
    {
      code: `
  const d = 'debounce'
  var a = require(\`lodash/\${d}\`)`,
    },
    {
      code: "const utils = require(__dirname + '/utils');",
      languageOptions: {
        globals: {
          __dirname: 'readonly',
        },
      },
    },
    {
      code: "const path = require('path'); const utils = require(path.join(__dirname, 'utils'));",
      languageOptions: {
        globals: {
          __dirname: 'readonly',
        },
      },
    },
    {
      code: "const pkg = require(require.resolve('eslint/package.json'));",
    },
  ],
  invalid: [
    {
      code: 'var a = require(c)',
      errors: [{ message: 'Found non-literal argument in require' }],
    },
    {
      code: 'var a = require(`${c}`)',
      errors: [{ message: 'Found non-literal argument in require' }],
    },
  ],
});
