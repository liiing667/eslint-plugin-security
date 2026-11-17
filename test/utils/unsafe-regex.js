'use strict';

const { analyzePattern } = require('../../utils/unsafe-regex');
const { deepStrictEqual, strictEqual } = require('assert');

describe('utils/unsafe-regex', () => {
  function kinds(pattern, options) {
    return analyzePattern(pattern, {}, options).map((finding) => finding.kind);
  }

  it('flags catastrophic exponential backtracking structures', () => {
    deepStrictEqual(kinds('(a+)+$'), ['nestedQuantifier']);
    deepStrictEqual(kinds('(x+x+)+y'), ['nestedQuantifier']);
    deepStrictEqual(kinds('(a|a)*'), ['ambiguousAlternation']);
    deepStrictEqual(kinds('(\\d+\\s?)*$'), ['nestedQuantifier']);
  });

  it('does not flag linear patterns', () => {
    deepStrictEqual(kinds('^d+1337d+$'), []);
    deepStrictEqual(kinds('a+b+'), []);
    deepStrictEqual(kinds('[a-z]+@[a-z]+\\.com'), []);
    deepStrictEqual(kinds('(ab+c)+'), []);
    deepStrictEqual(kinds('(foo|bar)*'), []);
    deepStrictEqual(kinds('(a{2,4}){2,4}'), []);
  });

  it('reports the structure location within the pattern', () => {
    const [finding] = analyzePattern('x(a+)+$');
    strictEqual(finding.start, 1);
    strictEqual(finding.end, 6);
    strictEqual('x(a+)+$'.slice(finding.start, finding.end), '(a+)+');
  });

  it('honors the maxStarHeight threshold', () => {
    strictEqual(analyzePattern('(a+)+').length, 1);
    deepStrictEqual(analyzePattern('(a+)+', {}, { maxStarHeight: 2 }), []);
    strictEqual(analyzePattern('((a+)+)+', {}, { maxStarHeight: 2 }).length, 1);
    deepStrictEqual(analyzePattern('((a+)+)+', {}, { maxStarHeight: 3 }), []);
  });

  it('detects super-linear adjacent quantifiers only when enabled', () => {
    deepStrictEqual(kinds('a*a*'), []);
    deepStrictEqual(kinds('a*a*', { checkAdjacentQuantifiers: true }), ['adjacentQuantifiers']);
    deepStrictEqual(kinds('a*b*', { checkAdjacentQuantifiers: true }), []);
  });

  it('flags quantified backreferences', () => {
    deepStrictEqual(kinds('(\\w)\\1+'), ['quantifiedBackreference']);
    deepStrictEqual(kinds('(\\w)\\1'), []);
  });

  it('ignores invalid patterns', () => {
    deepStrictEqual(analyzePattern('(a+'), []);
  });
});
