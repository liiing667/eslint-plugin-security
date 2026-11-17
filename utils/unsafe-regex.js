/**
 * In-repo static analysis for potentially unsafe regular expressions.
 *
 * Replaces the unmaintained `safe-regex` package with a configurable
 * heuristic analysis built on `@eslint-community/regexpp`. The analyzer
 * recognizes the classic structures behind exponential and super-linear
 * backtracking:
 *
 * - `nestedQuantifier`: an unbounded quantifier nested inside another
 *   unbounded quantifier where the inner match is ambiguous with what
 *   follows it (e.g. `(a+)+`, `(x+x+)+y`) — exponential backtracking.
 * - `ambiguousAlternation`: a quantified group whose alternation branches
 *   can start with the same characters (e.g. `(a|a)*`) — exponential
 *   backtracking.
 * - `adjacentQuantifiers`: two consecutive unbounded quantifiers whose
 *   character sets overlap (e.g. `a*a*`, `\w+\d+`) — super-linear
 *   backtracking. Opt-in via `checkAdjacentQuantifiers`.
 * - `quantifiedBackreference`: a backreference with an unbounded
 *   quantifier applied to it (e.g. `(\w+)\1+`) — super-linear
 *   backtracking.
 *
 * Character sets are tracked symbolically (chars, ranges, \d\w\s classes)
 * so that unambiguous nesting such as `(ab+c)+` is not flagged.
 */

'use strict';

const { RegExpParser, visitRegExpAST } = require('@eslint-community/regexpp');

const UNKNOWN = { unknown: true };

const CLASS_MEMBERS = {
  d: [0x30, 0x35, 0x39], // 0 5 9
  w: [0x61, 0x47, 0x30, 0x5f], // a G 0 _
  s: [0x20, 0x09, 0x0a], // space, tab, LF
};

const DEFAULT_SAMPLE = [0x61, 0x62, 0x41, 0x30, 0x39, 0x20, 0x5f, 0x2d, 0x2e, 0x0a, 0x2c, 0x2f];

function emptySet() {
  return { unknown: false, negate: false, chars: new Set(), ranges: [], classes: new Set(), notClasses: new Set() };
}

function isDigit(cp) {
  return cp >= 0x30 && cp <= 0x39;
}

function isWord(cp) {
  return isDigit(cp) || (cp >= 0x61 && cp <= 0x7a) || (cp >= 0x41 && cp <= 0x5a) || cp === 0x5f;
}

function isSpace(cp) {
  return cp === 0x20 || cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x0b || cp === 0x0c || cp === 0xa0 || cp === 0xfeff;
}

function setHas(set, cp) {
  let base = set.chars.has(cp) || set.ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
  if (!base) {
    for (const kind of set.classes) {
      if ((kind === 'd' && isDigit(cp)) || (kind === 'w' && isWord(cp)) || (kind === 's' && isSpace(cp))) {
        base = true;
        break;
      }
    }
  }
  if (!base) {
    for (const kind of set.notClasses) {
      if ((kind === 'd' && !isDigit(cp)) || (kind === 'w' && !isWord(cp)) || (kind === 's' && !isSpace(cp))) {
        base = true;
        break;
      }
    }
  }
  return set.negate ? !base : base;
}

/**
 * Conservative overlap test between two symbolic character sets.
 * Unknown sets are treated as overlapping everything.
 */
function setsOverlap(a, b) {
  if (a.unknown || b.unknown) {
    return true;
  }
  const candidates = new Set(DEFAULT_SAMPLE);
  for (const set of [a, b]) {
    for (const cp of set.chars) {
      candidates.add(cp);
    }
    for (const [lo, hi] of set.ranges) {
      candidates.add(lo);
      candidates.add(hi);
      candidates.add(lo + ((hi - lo) >> 1));
    }
    for (const kind of [...set.classes, ...set.notClasses]) {
      for (const cp of CLASS_MEMBERS[kind] || []) {
        candidates.add(cp);
      }
    }
  }
  for (const cp of candidates) {
    if (setHas(a, cp) && setHas(b, cp)) {
      return true;
    }
  }
  return false;
}

function mergeInto(target, source) {
  if (target.unknown) {
    return target;
  }
  if (source.unknown) {
    target.unknown = true;
    return target;
  }
  // Merging negated sets loses precision; fall back to unknown.
  if (target.negate || source.negate) {
    if (
      target.chars.size ||
      target.ranges.length ||
      target.classes.size ||
      target.notClasses.size ||
      source.chars.size ||
      source.ranges.length ||
      source.classes.size ||
      source.notClasses.size
    ) {
      target.unknown = true;
    }
    return target;
  }
  for (const cp of source.chars) {
    target.chars.add(cp);
  }
  target.ranges.push(...source.ranges);
  for (const kind of source.classes) {
    target.classes.add(kind);
  }
  for (const kind of source.notClasses) {
    target.notClasses.add(kind);
  }
  return target;
}

function setFromCharacterSet(element) {
  const set = emptySet();
  switch (element.kind) {
    case 'digit':
      (element.negate ? set.notClasses : set.classes).add('d');
      return set;
    case 'word':
      (element.negate ? set.notClasses : set.classes).add('w');
      return set;
    case 'space':
      (element.negate ? set.notClasses : set.classes).add('s');
      return set;
    case 'any': {
      // `.` matches anything except line terminators.
      set.negate = true;
      for (const cp of [0x0a, 0x0d, 0x2028, 0x2029]) {
        set.chars.add(cp);
      }
      return set;
    }
    default:
      // Unicode property escapes etc. — give up on precision.
      return UNKNOWN;
  }
}

function setFromCharacterClass(element) {
  const set = emptySet();
  set.negate = element.negate;
  for (const item of element.elements) {
    if (item.type === 'Character') {
      set.chars.add(item.value);
    } else if (item.type === 'CharacterClassRange') {
      set.ranges.push([item.min.value, item.max.value]);
    } else if (item.type === 'CharacterSet') {
      const sub = setFromCharacterSet(item);
      if (sub.unknown) {
        return UNKNOWN;
      }
      for (const kind of sub.classes) {
        set.classes.add(kind);
      }
      for (const kind of sub.notClasses) {
        set.notClasses.add(kind);
      }
      for (const cp of sub.chars) {
        set.chars.add(cp);
      }
    } else if (item.type === 'CharacterClass') {
      const sub = setFromCharacterClass(item);
      if (sub.unknown || sub.negate) {
        return UNKNOWN;
      }
      mergeInto(set, sub);
    } else {
      // Class intersections / subtractions (v-mode) — give up on precision.
      return UNKNOWN;
    }
  }
  return set;
}

function firstSetOfAlternative(alternative) {
  const result = emptySet();
  for (const element of alternative.elements) {
    if (element.type === 'Assertion') {
      continue;
    }
    if (element.type === 'Quantifier') {
      mergeInto(result, charSetOfElement(element.element));
      if (element.min === 0) {
        continue;
      }
      return result;
    }
    mergeInto(result, charSetOfElement(element));
    return result;
  }
  return result;
}

function firstSetOfGroup(group) {
  const result = emptySet();
  for (const alternative of group.alternatives) {
    mergeInto(result, firstSetOfAlternative(alternative));
  }
  return result;
}

function charSetOfElement(element) {
  switch (element.type) {
    case 'Character': {
      const set = emptySet();
      set.chars.add(element.value);
      return set;
    }
    case 'CharacterSet':
      return setFromCharacterSet(element);
    case 'CharacterClass':
      return setFromCharacterClass(element);
    case 'Group':
    case 'CapturingGroup':
      return firstSetOfGroup(element);
    default:
      // Backreferences, assertions, etc.
      return UNKNOWN;
  }
}

/**
 * Characters that may appear immediately after `elements[fromIndex]` within
 * the same alternative. Returns null when the alternative is exhausted.
 */
function firstOfElements(elements, fromIndex) {
  const result = emptySet();
  for (let i = fromIndex; i < elements.length; i++) {
    const element = elements[i];
    if (element.type === 'Assertion') {
      continue;
    }
    if (element.type === 'Quantifier') {
      mergeInto(result, charSetOfElement(element.element));
      if (element.min === 0) {
        continue;
      }
      return result;
    }
    mergeInto(result, charSetOfElement(element));
    return result;
  }
  return null;
}

/**
 * Compute the characters that can appear right after `quantifier` finishes
 * one iteration of `boundaryElement` (the element of the enclosing unbounded
 * quantifier), including wrapping around to the start of the next iteration.
 */
function followSetOfQuantifier(quantifier, boundaryElement) {
  const result = emptySet();
  let node = quantifier;
  for (;;) {
    const alternative = node.parent;
    if (!alternative || alternative.type !== 'Alternative') {
      return UNKNOWN;
    }
    const index = alternative.elements.indexOf(node);
    const rest = firstOfElements(alternative.elements, index + 1);
    if (rest) {
      return mergeInto(result, rest);
    }
    const group = alternative.parent;
    if (!group || (group.type !== 'Group' && group.type !== 'CapturingGroup')) {
      return UNKNOWN;
    }
    if (group === boundaryElement) {
      // Wrap around: the next iteration starts with the group's first set.
      return mergeInto(result, firstSetOfGroup(boundaryElement));
    }
    const parent = group.parent;
    if (parent && parent.type === 'Quantifier') {
      if (parent.max > 1) {
        mergeInto(result, charSetOfElement(group));
      }
      node = parent;
    } else {
      node = group;
    }
  }
}

function isUnbounded(quantifier) {
  return quantifier.max === Infinity;
}

/**
 * Analyze a regular expression pattern for unsafe backtracking structures.
 *
 * @param {string} pattern The pattern source (without delimiters/flags).
 * @param {object} [flags] `{ unicode, unicodeSets }` parse modes.
 * @param {object} [options] `{ maxStarHeight, checkAdjacentQuantifiers }`.
 * @returns {Array<{kind: string, start: number, end: number, starHeight?: number}>}
 *   Findings with pattern-relative offsets. Empty when the pattern is safe
 *   or cannot be parsed.
 */
function analyzePattern(pattern, flags = {}, options = {}) {
  const maxStarHeight = options.maxStarHeight == null ? 1 : options.maxStarHeight;
  const checkAdjacentQuantifiers = Boolean(options.checkAdjacentQuantifiers);

  let ast;
  try {
    const parser = new RegExpParser({
      unicode: Boolean(flags.unicode),
      unicodeSets: Boolean(flags.unicodeSets),
    });
    ast = parser.parsePattern(pattern, 0, pattern.length, {
      unicode: Boolean(flags.unicode),
      unicodeSets: Boolean(flags.unicodeSets),
    });
  } catch {
    // Invalid patterns are a syntax problem, not a security finding.
    return [];
  }

  const findings = [];
  const seen = new Set();

  function report(kind, start, end, extra) {
    const key = `${kind}:${start}:${end}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    findings.push({ kind, start, end, ...extra });
  }

  const quantifierStack = [];

  visitRegExpAST(ast, {
    onQuantifierEnter(quantifier) {
      if (isUnbounded(quantifier)) {
        const starHeight = quantifierStack.length + 1;
        const element = quantifier.element;

        // Ambiguous alternation: quantified group with overlapping branches.
        if ((element.type === 'Group' || element.type === 'CapturingGroup') && element.alternatives.length > 1) {
          const branchSets = element.alternatives.map(firstSetOfAlternative);
          let ambiguous = false;
          for (let i = 0; i < branchSets.length && !ambiguous; i++) {
            for (let j = i + 1; j < branchSets.length && !ambiguous; j++) {
              if (!branchSets[i].unknown && !branchSets[j].unknown && setsOverlap(branchSets[i], branchSets[j])) {
                ambiguous = true;
              }
            }
          }
          if (ambiguous) {
            report('ambiguousAlternation', quantifier.start, quantifier.end, { starHeight });
          }
        }

        // Nested quantifiers: ambiguous unbounded repetition inside
        // another unbounded repetition.
        if (starHeight > maxStarHeight && quantifierStack.length > 0) {
          const enclosing = quantifierStack[quantifierStack.length - 1];
          const innerSet = charSetOfElement(quantifier.element);
          const followSet = followSetOfQuantifier(quantifier, enclosing.element);
          if (innerSet.unknown || followSet.unknown || setsOverlap(innerSet, followSet)) {
            report('nestedQuantifier', enclosing.start, enclosing.end, { starHeight });
          }
        }

        quantifierStack.push(quantifier);
      }
    },
    onQuantifierLeave(quantifier) {
      if (isUnbounded(quantifier)) {
        quantifierStack.pop();
      }
    },
    onAlternativeEnter(alternative) {
      if (!checkAdjacentQuantifiers) {
        return;
      }
      for (let i = 0; i + 1 < alternative.elements.length; i++) {
        const current = alternative.elements[i];
        const next = alternative.elements[i + 1];
        if (current.type !== 'Quantifier' || next.type !== 'Quantifier' || !isUnbounded(current) || !isUnbounded(next)) {
          continue;
        }
        const currentSet = charSetOfElement(current.element);
        const nextSet = charSetOfElement(next.element);
        if (!currentSet.unknown && !nextSet.unknown && setsOverlap(currentSet, nextSet)) {
          report('adjacentQuantifiers', current.start, next.end, {});
        }
      }
    },
    onBackreferenceEnter(backreference) {
      const parent = backreference.parent;
      if (parent && parent.type === 'Quantifier' && isUnbounded(parent)) {
        report('quantifiedBackreference', parent.start, parent.end, {});
      }
    },
  });

  return findings;
}

module.exports = { analyzePattern };
