# Detects user-controlled request data used as the redirect target, which might allow an attacker to redirect users to arbitrary external sites (`security/detect-open-redirect`)

⚠️ This rule _warns_ in the ✅ `recommended` config.

<!-- end auto-generated rule header -->

Passing user-controlled data (e.g. `req.query`, `req.body` or `req.params`) to `res.redirect()`, `res.location()` or a `Location` response header allows an attacker to redirect victims to arbitrary external sites, which is commonly abused for phishing.

More information: [OWASP Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

## Rule Details

This rule reports request data flowing directly or through string concatenation/template literals into:

- `res.redirect(url)` / `res.redirect(status, url)`
- `res.location(url)`
- `res.set('Location', url)` / `res.setHeader('Location', url)` / `res.header('Location', url)`
- `res.writeHead(status, { Location: url })`

Examples of **incorrect** code for this rule:

```js
app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});
```

```js
app.get('/go', (req, res) => {
  // A static "https://" prefix does not prevent an open redirect.
  res.redirect('https://' + req.query.host);
});
```

Examples of **correct** code for this rule:

```js
app.get('/go', (req, res) => {
  // Root-relative paths stay on the same origin.
  res.redirect('/users/' + req.query.id);
});
```

```js
const url = require('url');

app.get('/go', (req, res) => {
  // Only the path of the parsed URL is used.
  res.redirect(url.parse(req.query.next).path);
});
```

Note that targets starting with `//` are NOT exempted, since `//evil.example` is a protocol-relative URL that leaves the current origin.

## Options

This rule takes an optional object with an `allowedPrefixes` property: an array of fixed URL prefixes that are considered trusted. A redirect target whose static leading portion starts with one of these prefixes is not reported.

```json
{
  "security/detect-open-redirect": ["warn", { "allowedPrefixes": ["https://trusted.example.com"] }]
}
```

With this configuration, the following is allowed:

```js
res.redirect('https://trusted.example.com' + req.query.next);
```

Be careful with prefixes that do not end in a path separator: `https://trusted.example.com` also matches `https://trusted.example.com.evil.example`.

## When Not To Use It

If your application never redirects based on request data, or you validate redirect targets through a dedicated allow-list helper, you can disable this rule.
