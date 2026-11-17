# Detects potentially unsafe regular expressions, which may take a very long time to run, blocking the event loop (`security/detect-unsafe-regex`)

⚠️ This rule _warns_ in the ✅ `recommended` config.

<!-- end auto-generated rule header -->

More information: [Regular Expression DoS and Node.js](../regular-expression-dos-and-node.md)

## Rule Details

This rule statically analyzes regular expression literals and string literals passed to `RegExp()` for structures that cause exponential or super-linear backtracking (ReDoS). The analysis is implemented in this repository (`utils/unsafe-regex.js`) on top of `@eslint-community/regexpp` and recognizes:

- **Nested unbounded quantifiers** — e.g. `(a+)+`, `(x+x+)+y` — exponential backtracking. Unambiguous nesting such as `(ab+c)+` (the inner quantified character can never start a new iteration) is _not_ reported.
- **Quantified alternations with overlapping branches** — e.g. `(a|a)*`, `(a|ab)*` — exponential backtracking.
- **Adjacent unbounded quantifiers with overlapping character sets** — e.g. `a*a*`, `\w+\d+` — super-linear backtracking. Disabled by default; enable with `checkAdjacentQuantifiers`.
- **Quantified backreferences** — e.g. `(\w)\1+` — super-linear backtracking.

Each report names the matched structure, quotes the offending sub-pattern, and gives its location (pattern index range, plus an exact source range for regex literals).

Examples of **incorrect** code for this rule:

```js
const re = /(a+)+$/;
const re2 = new RegExp('(x+x+)+y');
```

Examples of **correct** code for this rule:

```js
const re = /^d+1337d+$/;
const re2 = /(ab+c)+/;
```

## Options

This rule takes an options object:

```json
{
  "security/detect-unsafe-regex": [
    "warn",
    {
      "maxStarHeight": 1,
      "checkAdjacentQuantifiers": false,
      "allow": []
    }
  ]
}
```

- `maxStarHeight` (integer, default `1`): maximum allowed nesting depth of unbounded quantifiers (`*`, `+`, `{n,}`). Raise it if your codebase intentionally uses nested quantifiers that you have reviewed.
- `checkAdjacentQuantifiers` (boolean, default `false`): also report adjacent unbounded quantifiers whose character sets overlap (super-linear backtracking, e.g. `\w+\d+`). Off by default to keep false positives low.
- `allow` (string[], default `[]`): pattern sources to exempt from analysis. Use this to silence reviewed patterns that cannot be rewritten, e.g. `"allow": ["(a+)+$"]`.

## Migrating from `safe-regex`

Before this version, the rule delegated the whole pattern to the unmaintained `safe-regex` package and reported a single boolean verdict (`Unsafe Regular Expression`). The in-repo analysis changes behavior in the following ways:

- **Fewer false positives for unambiguous nesting.** `safe-regex` flagged any pattern with star height > 1 (e.g. `(ab+c)+`, `([^,]+,)+`). The new analysis tracks character sets symbolically and only reports nesting where an iteration boundary is actually ambiguous.
- **New finding kinds.** Ambiguous quantified alternations (`(a|a)*`) and quantified backreferences (`(\w)\1+`) are now reported; adjacent overlapping quantifiers (`a*a*`) can be reported by enabling `checkAdjacentQuantifiers`.
- **Configurable thresholds.** What used to be a hard-coded star-height limit of 1 is now the `maxStarHeight` option, and known-safe patterns can be exempted via `allow`.
- **Actionable reports.** Messages now identify the structure and its location (e.g. `nested unbounded quantifiers "(a+)+" at pattern index 0-5 ... star height 2 exceeds maxStarHeight 1`) instead of a bare `Unsafe Regular Expression`. Integrations that matched on the old message text should match on the `Unsafe Regular Expression` prefix or the rule's message IDs (`nestedQuantifier`, `ambiguousAlternation`, `adjacentQuantifiers`, `quantifiedBackreference`) instead.

If you relied on the old, stricter behavior for adjacent repetitions, enable `checkAdjacentQuantifiers`. If the new analysis flags a pattern you have reviewed, add its source to `allow` rather than disabling the rule.
