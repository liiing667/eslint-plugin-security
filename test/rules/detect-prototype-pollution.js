'use strict';

const RuleTester = require('eslint').RuleTester;
const tester = new RuleTester();

const ruleName = 'detect-prototype-pollution';

const Rule = require(`../../rules/${ruleName}`);

const objectAssignMessage = "Possible prototype pollution: attacker-controlled object passed to 'Object.assign'.";
const computedAssignmentMessage = 'Possible prototype pollution: unfiltered key from attacker-controlled object used in computed assignment.';

tester.run(`${ruleName} (Object.assign)`, Rule, {
  valid: [
    { code: 'Object.assign(target, { a: 1 });' },
    { code: 'Object.assign(Object.create(null), JSON.parse(input));' },
    { code: 'const target = Object.create(null); Object.assign(target, JSON.parse(input));' },
  ],
  invalid: [
    {
      code: 'Object.assign(target, JSON.parse(input));',
      errors: [{ message: objectAssignMessage, line: 1, column: 23, endLine: 1, endColumn: 40 }],
    },
    {
      code: 'const data = JSON.parse(input);\nObject.assign(config, data);',
      errors: [{ message: objectAssignMessage, line: 2, column: 23, endLine: 2, endColumn: 27 }],
    },
    {
      code: 'let data;\ndata = JSON.parse(input);\nObject.assign(config, data);',
      errors: [{ message: objectAssignMessage, line: 3, column: 23, endLine: 3, endColumn: 27 }],
    },
    {
      code: 'Object.assign(Object.create(null), JSON.parse(input));',
      options: [{ allowObjectCreateNull: false }],
      errors: [{ message: objectAssignMessage, line: 1, column: 36, endLine: 1, endColumn: 53 }],
    },
  ],
});

tester.run(`${ruleName} (key enumeration)`, Rule, {
  valid: [
    { code: 'for (const key in obj) { target[key] = obj[key]; }' },
    {
      code: [
        'function merge(target, source) {',
        '  for (const key in source) {',
        "    if (key === '__proto__' || key === 'constructor') continue;",
        '    target[key] = source[key];',
        '  }',
        '}',
        'merge(config, JSON.parse(input));',
      ].join('\n'),
    },
    {
      code: [
        'const data = JSON.parse(input);',
        'for (const key in data) {',
        "  if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;",
        '  target[key] = data[key];',
        '}',
      ].join('\n'),
    },
    {
      code: ['const data = JSON.parse(input);', 'const target = Object.create(null);', 'for (const key in data) {', '  target[key] = data[key];', '}'].join('\n'),
    },
    {
      code: ['const data = JSON.parse(input);', 'for (const key in data) {', "  if (key === '__proto__') continue;", '  target[key] = data[key];', '}'].join('\n'),
      options: [{ sensitiveKeys: ['__proto__'] }],
    },
  ],
  invalid: [
    {
      code: [
        'function merge(target, source) {',
        '  for (const key in source) {',
        "    if (typeof source[key] === 'object') {",
        '      merge(target[key], source[key]);',
        '    } else {',
        '      target[key] = source[key];',
        '    }',
        '  }',
        '}',
        'merge(config, JSON.parse(input));',
      ].join('\n'),
      errors: [{ message: computedAssignmentMessage, line: 6, column: 7, endLine: 6, endColumn: 18 }],
    },
    {
      code: ['const data = JSON.parse(input);', 'for (const key in data) {', '  target[key] = data[key];', '}'].join('\n'),
      errors: [{ message: computedAssignmentMessage, line: 3, column: 3, endLine: 3, endColumn: 14 }],
    },
    {
      code: ['const data = JSON.parse(input);', 'for (const key of Object.keys(data)) {', '  target[key] = data[key];', '}'].join('\n'),
      errors: [{ message: computedAssignmentMessage, line: 3, column: 3, endLine: 3, endColumn: 14 }],
    },
    {
      code: ['const data = JSON.parse(input);', 'for (const key in data) {', "  if (key === 'constructor') continue;", '  target[key] = data[key];', '}'].join('\n'),
      options: [{ sensitiveKeys: ['__proto__'] }],
      errors: [{ message: computedAssignmentMessage, line: 4, column: 3, endLine: 4, endColumn: 14 }],
    },
  ],
});
