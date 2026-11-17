'use strict';

const RuleTester = require('eslint').RuleTester;
const tester = new RuleTester();

const ruleName = 'detect-unsafe-regex';
const Rule = require(`../../rules/${ruleName}`);

tester.run(ruleName, Rule, {
  valid: [
    // Linear patterns must not be reported.
    { code: '/^d+1337d+$/' },
    { code: '/a+b+/' },
    { code: '/[a-z]+@[a-z]+\\.com/' },
    // Unambiguous nesting: the inner quantified char cannot start an iteration.
    { code: '/(ab+c)+/' },
    // Disjoint alternation branches.
    { code: '/(foo|bar)*/' },
    { code: '/(a|b)*/' },
    // Unquantified backreference is fine.
    { code: '/(\\w)\\1/' },
    // Bounded quantifiers do not nest unboundedly.
    { code: '/(a{2,4}){2,4}/' },
    // Threshold configuration: allow deeper nesting.
    { code: '/(a+)+$/', options: [{ maxStarHeight: 2 }] },
    { code: '/((a+)+)+/', options: [{ maxStarHeight: 3 }] },
    // Adjacent quantifiers are opt-in.
    { code: '/a*a*/' },
    { code: '/\\w+\\d+/' },
    // Exemptions.
    { code: '/(a+)+$/', options: [{ allow: ['(a+)+$'] }] },
    // Invalid patterns are ignored.
    { code: "new RegExp('(a+')" },
  ],
  invalid: [
    // Catastrophic backtracking structures.
    {
      code: '/(x+x+)+y/',
      errors: [
        {
          messageId: 'nestedQuantifier',
          data: { snippet: '(x+x+)+', start: '0', end: '7', starHeight: '2', maxStarHeight: '1' },
        },
      ],
    },
    {
      code: '/(a+)+$/',
      errors: [{ messageId: 'nestedQuantifier', data: { snippet: '(a+)+', start: '0', end: '5', starHeight: '2', maxStarHeight: '1' } }],
    },
    // Iterations separated only by optional whitespace are ambiguous too.
    {
      code: '/(\\s*,\\s*)+/',
      errors: [{ messageId: 'nestedQuantifier', data: { snippet: '(\\s*,\\s*)+', start: '0', end: '10', starHeight: '2', maxStarHeight: '1' } }],
    },
    {
      code: '/(a|a)*/',
      errors: [{ messageId: 'ambiguousAlternation', data: { snippet: '(a|a)*', start: '0', end: '6' } }],
    },
    {
      code: '/(\\w)\\1+/',
      errors: [{ messageId: 'quantifiedBackreference', data: { snippet: '\\1+', start: '4', end: '7' } }],
    },
    // Stricter threshold flags previously acceptable nesting.
    {
      code: '/(a+)+$/',
      options: [{ maxStarHeight: 0 }],
      errors: [{ messageId: 'nestedQuantifier', data: { snippet: '(a+)+', start: '0', end: '5', starHeight: '2', maxStarHeight: '0' } }],
    },
    // Super-linear structures are reported when enabled.
    {
      code: '/a*a*/',
      options: [{ checkAdjacentQuantifiers: true }],
      errors: [{ messageId: 'adjacentQuantifiers', data: { snippet: 'a*a*', start: '0', end: '4' } }],
    },
    {
      code: '/\\w+\\d+/',
      options: [{ checkAdjacentQuantifiers: true }],
      errors: [{ messageId: 'adjacentQuantifiers', data: { snippet: '\\w+\\d+', start: '0', end: '6' } }],
    },
    // Reports point at the offending structure inside the literal.
    {
      code: '/x(a+)+$/',
      errors: [
        {
          messageId: 'nestedQuantifier',
          data: { snippet: '(a+)+', start: '1', end: '6', starHeight: '2', maxStarHeight: '1' },
          line: 1,
          column: 3,
          endColumn: 8,
        },
      ],
    },
  ],
});

tester.run(`${ruleName} (new RegExp)`, Rule, {
  valid: [
    { code: "new RegExp('^d+1337d+$')" },
    { code: "RegExp('^d+1337d+$')" },
    { code: "new RegExp('(a+)+$')", options: [{ maxStarHeight: 2 }] },
    { code: "new RegExp('(a+)+$')", options: [{ allow: ['(a+)+$'] }] },
    // Non-string patterns are ignored.
    { code: 'new RegExp(42)' },
  ],
  invalid: [
    {
      code: "new RegExp('(x+x+)+y')",
      errors: [{ messageId: 'nestedQuantifier', data: { snippet: '(x+x+)+', start: '0', end: '7', starHeight: '2', maxStarHeight: '1' } }],
    },
    {
      code: "RegExp('(x+x+)+y')",
      errors: [{ messageId: 'nestedQuantifier', data: { snippet: '(x+x+)+', start: '0', end: '7', starHeight: '2', maxStarHeight: '1' } }],
    },
    {
      code: "new RegExp('(a|a)*', 'u')",
      errors: [{ messageId: 'ambiguousAlternation', data: { snippet: '(a|a)*', start: '0', end: '6' } }],
    },
  ],
});
