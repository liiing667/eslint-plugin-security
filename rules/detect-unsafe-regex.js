/**
 * Check if a regular expression is vulnerable to ReDoS using the in-repo
 * configurable static analysis in `utils/unsafe-regex.js`.
 * @author Adam Baldwin
 */

'use strict';

//-----------------------------------------------------------------------------
// Requirements
//-----------------------------------------------------------------------------

const { analyzePattern } = require('../utils/unsafe-regex');

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

const KIND_TO_MESSAGE_ID = {
  nestedQuantifier: 'nestedQuantifier',
  ambiguousAlternation: 'ambiguousAlternation',
  adjacentQuantifiers: 'adjacentQuantifiers',
  quantifiedBackreference: 'quantifiedBackreference',
};

/**
 * Split a regular expression literal's raw text into pattern and flags.
 * @param {string} raw The literal source text, e.g. `/a+/gi`.
 * @returns {{pattern: string, flagsText: string}}
 */
function splitLiteral(raw) {
  const lastSlash = raw.lastIndexOf('/');
  return {
    pattern: raw.slice(1, lastSlash),
    flagsText: raw.slice(lastSlash + 1),
  };
}

function parseFlags(flagsText) {
  return {
    unicode: flagsText.includes('u'),
    unicodeSets: flagsText.includes('v'),
  };
}

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Detects potentially unsafe regular expressions, which may take a very long time to run, blocking the event loop.',
      category: 'Possible Security Vulnerability',
      recommended: true,
      url: 'https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-unsafe-regex.md',
    },
    schema: [
      {
        type: 'object',
        properties: {
          maxStarHeight: {
            type: 'integer',
            minimum: 0,
            default: 1,
            description: 'Maximum allowed nesting depth of unbounded quantifiers (`*`, `+`, `{n,}`) before a pattern is reported.',
          },
          checkAdjacentQuantifiers: {
            type: 'boolean',
            default: false,
            description: 'Also report adjacent unbounded quantifiers with overlapping character sets (super-linear backtracking).',
          },
          allow: {
            type: 'array',
            items: { type: 'string' },
            uniqueItems: true,
            default: [],
            description: 'Pattern sources to exempt from analysis, e.g. ["(a+)+$"].',
          },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      nestedQuantifier:
        'Unsafe Regular Expression: nested unbounded quantifiers "{{snippet}}" at pattern index {{start}}-{{end}} can cause exponential backtracking (star height {{starHeight}} exceeds maxStarHeight {{maxStarHeight}}).',
      ambiguousAlternation:
        'Unsafe Regular Expression: quantified alternation "{{snippet}}" at pattern index {{start}}-{{end}} has branches with overlapping prefixes, which can cause exponential backtracking.',
      adjacentQuantifiers:
        'Unsafe Regular Expression: adjacent unbounded quantifiers "{{snippet}}" at pattern index {{start}}-{{end}} match overlapping characters, which can cause super-linear backtracking.',
      quantifiedBackreference:
        'Unsafe Regular Expression: quantified backreference "{{snippet}}" at pattern index {{start}}-{{end}} re-matches variable-length captured text, which can cause super-linear backtracking.',
    },
  },
  create(context) {
    const sourceCode = context.sourceCode || context.getSourceCode();
    const options = context.options[0] || {};
    const maxStarHeight = options.maxStarHeight == null ? 1 : options.maxStarHeight;
    const checkAdjacentQuantifiers = Boolean(options.checkAdjacentQuantifiers);
    const allow = new Set(options.allow || []);

    function analyze(pattern, flags) {
      if (allow.has(pattern)) {
        return [];
      }
      return analyzePattern(pattern, flags, { maxStarHeight, checkAdjacentQuantifiers });
    }

    function reportFindings(node, pattern, findings, patternStartColumn) {
      for (const finding of findings) {
        const report = {
          node,
          messageId: KIND_TO_MESSAGE_ID[finding.kind],
          data: {
            snippet: pattern.slice(finding.start, finding.end),
            start: String(finding.start),
            end: String(finding.end),
            starHeight: String(finding.starHeight || 0),
            maxStarHeight: String(maxStarHeight),
          },
        };
        if (patternStartColumn != null) {
          // Point at the offending structure inside the regex literal.
          report.loc = {
            start: { line: node.loc.start.line, column: node.loc.start.column + patternStartColumn + finding.start },
            end: { line: node.loc.start.line, column: node.loc.start.column + patternStartColumn + finding.end },
          };
        }
        context.report(report);
      }
    }

    return {
      Literal: function (node) {
        const token = sourceCode.getTokens(node)[0];
        if (token.type !== 'RegularExpression') {
          return;
        }
        const { pattern, flagsText } = splitLiteral(token.value);
        const findings = analyze(pattern, parseFlags(flagsText));
        // The pattern starts one column after the opening `/`.
        reportFindings(node, pattern, findings, 1);
      },
      // `RegExp(pattern)` without `new` creates a regular expression too
      'NewExpression, CallExpression': function (node) {
        if (node.callee.name !== 'RegExp' || !node.arguments || node.arguments.length === 0) {
          return;
        }
        const patternArg = node.arguments[0];
        if (patternArg.type !== 'Literal' || typeof patternArg.value !== 'string') {
          return;
        }
        const flagsArg = node.arguments[1];
        const flagsText = flagsArg && flagsArg.type === 'Literal' && typeof flagsArg.value === 'string' ? flagsArg.value : '';
        const findings = analyze(patternArg.value, parseFlags(flagsText));
        // Offsets inside a string literal do not map cleanly onto source
        // columns (escapes), so report on the whole expression instead.
        reportFindings(node, patternArg.value, findings, null);
      },
    };
  },
};
