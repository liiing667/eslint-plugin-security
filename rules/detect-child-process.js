/**
 * Tries to detect instances of child_process
 * @author Adam Baldwin
 */

'use strict';

const { getImportAccessPath } = require('../utils/import-utils');
const { isStaticExpression } = require('../utils/is-static-expression');
const childProcessPackageNames = ['child_process', 'node:child_process'];
const execFunctionNames = new Set(['exec', 'execSync']);
const spawnFunctionNames = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);

/**
 * Checks whether the given arguments enable the `shell` option.
 *
 * The options object can be the second or third argument depending on
 * whether the `args` argument is provided. Only an explicitly disabled
 * `shell` (`false`, `0`, or an empty string) counts as safe; unknown or
 * non-literal values are treated as enabled since the option may be
 * turned on at runtime.
 *
 * @param {import("estree").Node[]} args The call arguments.
 * @returns {boolean} `true` when the `shell` option is (or may be) enabled.
 */
function isShellEnabled(args) {
  const optionsNode = args.slice(1).find((argument) => argument.type === 'ObjectExpression');
  if (!optionsNode) {
    return false;
  }
  const shellProperty = optionsNode.properties.find(
    (property) =>
      property.type === 'Property' &&
      !property.computed &&
      ((property.key.type === 'Identifier' && property.key.name === 'shell') || (property.key.type === 'Literal' && property.key.value === 'shell'))
  );
  if (!shellProperty) {
    return false;
  }
  const value = shellProperty.value;
  return value.type !== 'Literal' || Boolean(value.value);
}

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Detects instances of "child_process" & non-literal "exec()" calls.',
      category: 'Possible Security Vulnerability',
      recommended: true,
      url: 'https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-child-process.md',
    },
  },
  create(context) {
    const sourceCode = context.sourceCode || context.getSourceCode();
    return {
      CallExpression: function (node) {
        if (node.callee.name === 'require') {
          const args = node.arguments[0];
          if (
            args &&
            args.type === 'Literal' &&
            childProcessPackageNames.includes(args.value) &&
            node.parent.type !== 'VariableDeclarator' &&
            node.parent.type !== 'AssignmentExpression' &&
            node.parent.type !== 'MemberExpression'
          ) {
            context.report({ node: node, message: 'Found require("' + args.value + '")' });
          }
          return;
        }

        if (!node.arguments.length) {
          return;
        }

        const scope = sourceCode.getScope ? sourceCode.getScope(node) : context.getScope();

        const pathInfo = getImportAccessPath({
          node: node.callee,
          scope,
          packageNames: childProcessPackageNames,
        });
        const fnName = pathInfo && pathInfo.path.length === 1 && pathInfo.path[0];
        if (!fnName) {
          return;
        }

        const firstArgument = node.arguments[0];
        const firstArgumentIsStatic = isStaticExpression({
          node: firstArgument,
          scope,
        });

        if (execFunctionNames.has(fnName)) {
          // Reports non-literal `exec()`/`execSync()` calls.
          if (!firstArgumentIsStatic) {
            context.report({ node: node, message: `Found child_process.${fnName}() with non Literal first argument` });
          }
          return;
        }

        if (spawnFunctionNames.has(fnName)) {
          // `spawn()`/`execFile()` and their sync variants are only vulnerable
          // when the `shell` option is enabled.
          if (isShellEnabled(node.arguments) && !firstArgumentIsStatic) {
            context.report({
              node: node,
              message: `Found child_process.${fnName}() with non Literal first argument and shell enabled`,
            });
          }
        }
      },
    };
  },
};
