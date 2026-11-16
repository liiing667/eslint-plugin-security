/**
 * Tries to detect open redirects where user-controlled request data is used as the redirect target
 */

'use strict';

const { findVariable } = require('../utils/find-variable');
const { getImportAccessPath } = require('../utils/import-utils');

const URL_PACKAGE_NAMES = ['url', 'node:url'];
const REQ_DATA_PROPERTIES = new Set(['query', 'body', 'params']);
const RESPONSE_OBJECT_NAMES = new Set(['res', 'response']);
const REDIRECT_METHOD_NAMES = new Set(['redirect', 'location']);
const HEADER_METHOD_NAMES = new Set(['set', 'setHeader', 'header']);

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Detects user-controlled request data used as the redirect target, which might allow an attacker to redirect users to arbitrary external sites.',
      category: 'Possible Security Vulnerability',
      recommended: true,
      url: 'https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-open-redirect.md',
    },
    schema: [
      {
        type: 'object',
        properties: {
          allowedPrefixes: {
            type: 'array',
            items: { type: 'string' },
            uniqueItems: true,
            default: [],
          },
        },
        additionalProperties: false,
      },
    ],
  },
  create(context) {
    const sourceCode = context.sourceCode || context.getSourceCode();
    const options = context.options[0] || {};
    const allowedPrefixes = options.allowedPrefixes || [];

    /**
     * @param {import("estree").Node} node
     * @returns {import("eslint").Scope.Scope}
     */
    function getScope(node) {
      return sourceCode.getScope ? sourceCode.getScope(node) : context.getScope();
    }

    /**
     * Checks whether the given node is a member access rooted at `req`,
     * reading user-controlled data such as `req.query`, `req.body` or `req.params`.
     *
     * @param {import("estree").Node} node The node to check.
     * @returns {boolean} if true, the node reads user-controlled request data.
     */
    function isReqDataAccess(node) {
      if (node.type !== 'MemberExpression') {
        return false;
      }
      let inner = node;
      while (inner.object.type === 'MemberExpression') {
        inner = inner.object;
      }
      if (inner.object.type !== 'Identifier' || inner.object.name !== 'req') {
        return false;
      }
      const propertyName = inner.computed
        ? inner.property.type === 'Literal' && typeof inner.property.value === 'string'
          ? inner.property.value
          : null
        : inner.property.type === 'Identifier'
          ? inner.property.name
          : null;
      return Boolean(propertyName && REQ_DATA_PROPERTIES.has(propertyName));
    }

    /**
     * Checks whether the given node is a `url.parse(...).path` (or `.pathname`) access,
     * which strips the authority part of the URL and is therefore not an open redirect.
     *
     * @param {import("estree").Node} node The node to check.
     * @param {import("eslint").Scope.Scope} scope The scope of the given node.
     * @returns {boolean} if true, the node only takes the path of a parsed URL.
     */
    function isUrlParsePathAccess(node, scope) {
      if (node.type !== 'MemberExpression' || node.computed || node.property.type !== 'Identifier') {
        return false;
      }
      if (node.property.name !== 'path' && node.property.name !== 'pathname') {
        return false;
      }
      const object = node.object;
      if (object.type !== 'CallExpression') {
        return false;
      }
      const pathInfo = getImportAccessPath({
        node: object.callee,
        scope,
        packageNames: URL_PACKAGE_NAMES,
      });
      return Boolean(pathInfo && pathInfo.path.length === 1 && pathInfo.path[0] === 'parse');
    }

    /**
     * Checks whether the given expression may contain user-controlled request data.
     *
     * @param {import("estree").Node} node The node to check.
     * @param {import("eslint").Scope.Scope} scope The scope of the given node.
     * @param {Set<import("estree").Node>} [seen] Nodes already visited, to guard infinite loops.
     * @returns {boolean} if true, the expression may be tainted by request data.
     */
    function isTainted(node, scope, seen = new Set()) {
      if (!node || seen.has(node)) {
        return false;
      }
      seen.add(node);
      switch (node.type) {
        case 'Literal':
          return false;
        case 'TemplateLiteral':
          return node.expressions.some((expression) => isTainted(expression, scope, seen));
        case 'BinaryExpression':
        case 'LogicalExpression':
          return isTainted(node.left, scope, seen) || isTainted(node.right, scope, seen);
        case 'ConditionalExpression':
          return isTainted(node.consequent, scope, seen) || isTainted(node.alternate, scope, seen);
        case 'MemberExpression':
          if (isUrlParsePathAccess(node, scope)) {
            return false;
          }
          return isReqDataAccess(node) || isTainted(node.object, scope, seen);
        case 'Identifier': {
          const variable = findVariable(scope, node.name);
          if (!variable || variable.defs.length !== 1) {
            return false;
          }
          const def = variable.defs[0];
          if (def.type !== 'Variable' || !def.node.init) {
            return false;
          }
          if (!variable.references.every((ref) => ref.isReadOnly() || ref.identifier === def.name)) {
            return false;
          }
          return isTainted(def.node.init, scope, seen);
        }
        case 'CallExpression':
          return node.arguments.some((argument) => isTainted(argument, scope, seen));
        default:
          return false;
      }
    }

    /**
     * Computes the leading static string of the given expression,
     * e.g. `"/users/"` for `"/users/" + req.query.id`.
     *
     * @param {import("estree").Node} node The node to check.
     * @param {import("eslint").Scope.Scope} scope The scope of the given node.
     * @param {Set<import("estree").Node>} [seen] Nodes already visited, to guard infinite loops.
     * @returns {string} the static prefix, or an empty string if unknown.
     */
    function getStaticPrefix(node, scope, seen = new Set()) {
      if (!node || seen.has(node)) {
        return '';
      }
      seen.add(node);
      switch (node.type) {
        case 'Literal':
          return typeof node.value === 'string' ? node.value : '';
        case 'TemplateLiteral': {
          let prefix = node.quasis[0].value.cooked || '';
          for (let index = 0; index < node.expressions.length; index++) {
            const expression = node.expressions[index];
            if (expression.type === 'Literal' && typeof expression.value === 'string') {
              prefix += expression.value + (node.quasis[index + 1].value.cooked || '');
            } else {
              break;
            }
          }
          return prefix;
        }
        case 'BinaryExpression': {
          if (node.operator !== '+') {
            return '';
          }
          const left = getStaticPrefix(node.left, scope, seen);
          if (node.left.type === 'Literal' && typeof node.left.value === 'string') {
            return left + getStaticPrefix(node.right, scope, seen);
          }
          return left;
        }
        case 'Identifier': {
          const variable = findVariable(scope, node.name);
          if (!variable || variable.defs.length !== 1) {
            return '';
          }
          const def = variable.defs[0];
          if (def.type !== 'Variable' || !def.node.init) {
            return '';
          }
          if (!variable.references.every((ref) => ref.isReadOnly() || ref.identifier === def.name)) {
            return '';
          }
          return getStaticPrefix(def.node.init, scope, seen);
        }
        default:
          return '';
      }
    }

    /**
     * Checks whether the given redirect target is exempted:
     * a root-relative path (`/...`), an allowed prefix, or a `url.parse(...).path` access.
     *
     * @param {import("estree").Node} node The redirect target expression.
     * @param {import("eslint").Scope.Scope} scope The scope of the given node.
     * @returns {boolean} if true, the target is considered safe.
     */
    function isExemptTarget(node, scope) {
      if (isUrlParsePathAccess(node, scope)) {
        return true;
      }
      const prefix = getStaticPrefix(node, scope);
      if (prefix) {
        // Root-relative paths stay on the same origin. Protocol-relative
        // URLs (`//evil.example`) are NOT exempted.
        if (prefix.startsWith('/') && !prefix.startsWith('//')) {
          return true;
        }
        if (allowedPrefixes.some((allowed) => prefix.startsWith(allowed))) {
          return true;
        }
      }
      return false;
    }

    /**
     * Reports the given redirect target if it is tainted and not exempted.
     *
     * @param {import("estree").Node} node The redirect target expression.
     * @param {import("eslint").Scope.Scope} scope The scope of the given node.
     * @param {string} sink A description of the sink, e.g. "res.redirect".
     */
    function checkTarget(node, scope, sink) {
      if (!node || isExemptTarget(node, scope)) {
        return;
      }
      if (isTainted(node, scope)) {
        context.report({
          node,
          message: `Possible open redirect: user-controlled request data passed to ${sink}`,
        });
      }
    }

    /**
     * @param {import("estree").Node} node
     * @returns {string | null}
     */
    function getStaticKeyName(node) {
      if (node.type === 'Identifier') {
        return node.name;
      }
      if (node.type === 'Literal' && typeof node.value === 'string') {
        return node.value;
      }
      return null;
    }

    return {
      CallExpression(node) {
        const callee = node.callee;
        if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') {
          return;
        }
        if (callee.object.type !== 'Identifier' || !RESPONSE_OBJECT_NAMES.has(callee.object.name)) {
          return;
        }
        const methodName = callee.property.name;
        const scope = getScope(node);

        if (REDIRECT_METHOD_NAMES.has(methodName)) {
          // `res.redirect(url)` / `res.redirect(status, url)` and `res.location(url)`
          const target = methodName === 'redirect' && node.arguments.length > 1 ? node.arguments[node.arguments.length - 1] : node.arguments[0];
          checkTarget(target, scope, `res.${methodName}`);
          return;
        }
        if (HEADER_METHOD_NAMES.has(methodName)) {
          // `res.setHeader('Location', url)` / `res.set(...)` / `res.header(...)`
          const [nameArgument, valueArgument] = node.arguments;
          if (nameArgument && nameArgument.type === 'Literal' && typeof nameArgument.value === 'string' && nameArgument.value.toLowerCase() === 'location') {
            checkTarget(valueArgument, scope, `res.${methodName}("Location", ...)`);
          }
          return;
        }
        if (methodName === 'writeHead') {
          // `res.writeHead(302, { Location: url })`
          const headersArgument = node.arguments[node.arguments.length - 1];
          if (!headersArgument || headersArgument.type !== 'ObjectExpression') {
            return;
          }
          for (const property of headersArgument.properties) {
            if (property.type !== 'Property' || property.computed) {
              continue;
            }
            const keyName = getStaticKeyName(property.key);
            if (keyName && keyName.toLowerCase() === 'location') {
              checkTarget(property.value, scope, 'res.writeHead(..., { Location: ... })');
            }
          }
        }
      },
    };
  },
};
