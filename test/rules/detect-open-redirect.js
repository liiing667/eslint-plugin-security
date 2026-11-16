'use strict';

const RuleTester = require('eslint').RuleTester;
const tester = new RuleTester();

const ruleName = 'detect-open-redirect';

tester.run(ruleName, require(`../../rules/${ruleName}`), {
  valid: [
    // static targets are not user-controlled
    `res.redirect('/dashboard')`,
    `res.redirect('https://example.com/landing')`,
    `res.location('/users')`,
    `res.setHeader('Location', '/home')`,
    // not derived from the request
    `res.redirect(config.fallbackUrl)`,
    `const target = '/a/' + '/b'; res.redirect(target);`,
    // not a redirect sink
    `foo.redirect(req.query.next)`,
    `res.download(req.query.file)`,
    `res.setHeader('Content-Type', req.query.type)`,
    // "/" prefix exemption: root-relative targets stay on the same origin
    `res.redirect('/users/' + req.query.id)`,
    'res.redirect(`/users/${req.query.id}`)',
    `const prefix = '/accounts'; res.redirect(prefix + req.query.id);`,
    // whitelist prefix exemption
    {
      code: `res.redirect('https://trusted.example.com' + req.query.next)`,
      options: [{ allowedPrefixes: ['https://trusted.example.com'] }],
    },
    {
      code: 'res.redirect(`https://trusted.example.com/${req.query.next}`)',
      options: [{ allowedPrefixes: ['https://trusted.example.com'] }],
    },
    // url.parse(...).path exemption: only the path of the parsed URL is used
    `const url = require('url');
     res.redirect(url.parse(req.query.next).path);`,
    `const url = require('url');
     res.redirect(url.parse(req.query.next).pathname);`,
    `const { parse } = require('url');
     const target = parse(req.query.next).path;
     res.redirect(target);`,
    `import url from 'node:url';
     res.location(url.parse(req.body.returnTo).path);`,
  ],
  invalid: [
    // direct pass-through of request data
    {
      code: `res.redirect(req.query.next)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    {
      code: `res.redirect(301, req.query.next)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    {
      code: `res.location(req.body.returnTo)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.location' }],
    },
    {
      code: `res.setHeader('Location', req.query.next)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.setHeader("Location", ...)' }],
    },
    {
      code: `res.set('Location', req.params.target)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.set("Location", ...)' }],
    },
    {
      code: `res.writeHead(302, { Location: req.query.next })`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.writeHead(..., { Location: ... })' }],
    },
    // pass-through via a local variable
    {
      code: `const next = req.query.next;
             res.redirect(next);`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    {
      code: `const { next } = req.query;
             res.redirect(next);`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    // concatenation bypass: a static "https://" prefix does not make it safe
    {
      code: `res.redirect('https://' + req.query.host)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    {
      code: 'res.redirect(`https://${req.query.host}/login`)',
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    {
      code: `const target = 'https://' + req.body.host;
             res.redirect(target);`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    // protocol-relative URLs can leave the origin
    {
      code: `res.redirect('//' + req.query.host)`,
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
    // a whitelist that does not match the static prefix does not exempt
    {
      code: `res.redirect('https://evil.example.com' + req.query.next)`,
      options: [{ allowedPrefixes: ['https://trusted.example.com'] }],
      errors: [{ message: 'Possible open redirect: user-controlled request data passed to res.redirect' }],
    },
  ],
});
