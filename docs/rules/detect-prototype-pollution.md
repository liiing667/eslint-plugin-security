# Detects prototype pollution when attacker-controlled objects are merged or copied into other objects without filtering sensitive keys (`security/detect-prototype-pollution`)

⚠️ This rule _warns_ in the ✅ `recommended` config.

<!-- end auto-generated rule header -->

Prototype pollution happens when an attacker is able to inject `__proto__`, `constructor` or `prototype` properties into a plain object. The most common sinks are `Object.assign` and recursive "merge" helpers that copy every key of an attacker-controlled object (for example the result of `JSON.parse` on user input) into another object.

This rule tracks attacker-controlled objects (such as `JSON.parse` results) through same-file assignments and function parameters, and reports when they reach a sensitive sink:

- `Object.assign(target, source)` with an attacker-controlled `source`.
- `target[key] = value` inside a `for...in` loop (or `for...of Object.keys(...)`) that enumerates an attacker-controlled object without filtering the key.

Examples of **incorrect** code for this rule:

```js
Object.assign(target, JSON.parse(input));
```

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
merge(config, JSON.parse(input));
```

Examples of **correct** code for this rule:

```js
// Merging into a null-prototype object is safe.
Object.assign(Object.create(null), JSON.parse(input));
```

```js
function merge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    target[key] = source[key];
  }
}
```

## Options

This rule takes an optional object with the following properties:

- `sensitiveKeys` (default `["__proto__", "constructor", "prototype"]`): the keys considered dangerous. A key enumeration is treated as safe when the key variable is compared against (or filtered with an array containing) one of these keys.
- `allowObjectCreateNull` (default `true`): when `true`, sinks whose target object is created with `Object.create(null)` are considered safe.

Example configuration:

```json
{
  "security/detect-prototype-pollution": [
    "warn",
    {
      "sensitiveKeys": ["__proto__"],
      "allowObjectCreateNull": true
    }
  ]
}
```

## Further Reading

- [Prototype pollution](https://owasp.org/www-community/attacks/Prototype_Pollution)
