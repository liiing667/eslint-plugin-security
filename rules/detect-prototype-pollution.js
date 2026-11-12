/**
 * Tries to detect prototype pollution caused by merging or copying
 * attacker-controlled objects (e.g. `JSON.parse` output) into other objects.
 * @author eslint-plugin-security contributors
 */

'use strict';

const { findVariable } = require('../utils/find-variable');

const DEFAULT_SENSITIVE_KEYS = ['__proto__', 'constructor', 'prototype'];

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

/**
 * Checks whether a node is a call to `Object.create(null)`.
 * @param {ASTNode} node The node to check.
 * @returns {boolean} True when the node is `Object.create(null)`.
 */
function isObjectCreateNull(node) {
  return (
    node &&
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'Object' &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'create' &&
    node.arguments.length > 0 &&
    node.arguments[0].type === 'Literal' &&
    node.arguments[0].value === null
  );
}

/**
 * Checks whether a node is a call to `JSON.parse(...)`.
 * @param {ASTNode} node The node to check.
 * @returns {boolean} True when the node is a `JSON.parse` call.
 */
function isJsonParse(node) {
  return (
    node &&
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'JSON' &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'parse'
  );
}

/**
 * Recursively walks an AST subtree.
 * @param {ASTNode} node The root of the subtree.
 * @param {Object} visitorKeys The visitor keys of the source code.
 * @param {Function} callback Invoked for every node; return true to stop.
 * @returns {boolean} True when the callback stopped the walk.
 */
function walk(node, visitorKeys, callback) {
  if (!node || typeof node.type !== 'string') {
    return false;
  }
  if (callback(node)) {
    return true;
  }
  const keys = visitorKeys[node.type] || Object.keys(node).filter((key) => key !== 'parent');
  for (const key of keys) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const element of child) {
        if (element && walk(element, visitorKeys, callback)) {
          return true;
        }
      }
    } else if (child && walk(child, visitorKeys, callback)) {
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Detects prototype pollution when attacker-controlled objects are merged or copied into other objects without filtering sensitive keys.',
      category: 'Possible Security Vulnerability',
      recommended: true,
      url: 'https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-prototype-pollution.md',
    },
    schema: [
      {
        type: 'object',
        properties: {
          sensitiveKeys: {
            type: 'array',
            items: { type: 'string' },
            uniqueItems: true,
          },
          allowObjectCreateNull: {
            type: 'boolean',
          },
        },
        additionalProperties: false,
      },
    ],
  },
  create(context) {
    const sourceCode = context.sourceCode || context.getSourceCode();
    const options = context.options[0] || {};
    const sensitiveKeys = options.sensitiveKeys || DEFAULT_SENSITIVE_KEYS;
    const allowObjectCreateNull = options.allowObjectCreateNull !== false;
    const visitorKeys = sourceCode.visitorKeys;

    /**
     * Resolves an Identifier to its scope variable.
     * @param {ASTNode} node The identifier node.
     * @returns {Variable|null} The resolved variable, if any.
     */
    function resolveVariable(node) {
      if (!node || node.type !== 'Identifier') {
        return null;
      }
      const scope = sourceCode.getScope ? sourceCode.getScope(node) : context.getScope();
      return findVariable(scope, node.name);
    }

    /**
     * Gets the expressions a variable was initialized or assigned with.
     * @param {Variable} variable The variable to inspect.
     * @returns {ASTNode[]} The initializing expressions found in this file.
     */
    function getAssignedExpressions(variable) {
      const expressions = [];
      for (const def of variable.defs) {
        if (def.type === 'Variable' && def.node.init) {
          expressions.push(def.node.init);
        }
      }
      for (const reference of variable.references) {
        const identifier = reference.identifier;
        if (reference.isWrite() && identifier.parent.type === 'AssignmentExpression' && identifier.parent.operator === '=' && identifier.parent.left === identifier) {
          expressions.push(identifier.parent.right);
        }
      }
      return expressions;
    }

    /**
     * Checks whether an expression is known to produce a null-prototype object.
     * @param {ASTNode} node The expression to check.
     * @returns {boolean} True when the expression is null-prototype safe.
     */
    function isNullPrototypeObject(node) {
      if (!allowObjectCreateNull) {
        return false;
      }
      if (isObjectCreateNull(node)) {
        return true;
      }
      const variable = resolveVariable(node);
      if (!variable) {
        return false;
      }
      return getAssignedExpressions(variable).some((expression) => isObjectCreateNull(expression));
    }

    //--------------------------------------------------------------------------
    // Taint tracking
    //--------------------------------------------------------------------------

    const allVariables = new Set();
    const taintedVariables = new Set();
    const callExpressions = [];

    /**
     * Checks whether an expression is tainted by attacker-controlled data.
     * @param {ASTNode} node The expression to check.
     * @returns {boolean} True when the expression is attacker-controlled.
     */
    function isTaintedExpression(node) {
      if (!node) {
        return false;
      }
      if (isJsonParse(node)) {
        return true;
      }
      if (node.type === 'Identifier') {
        const variable = resolveVariable(node);
        return variable !== null && taintedVariables.has(variable);
      }
      return false;
    }

    /**
     * Collects every variable and call expression in the analyzed file.
     * @param {ASTNode} program The program node.
     */
    function collectFacts(program) {
      const globalScope = sourceCode.getScope ? sourceCode.getScope(program) : context.getScope();
      const stack = [globalScope];
      while (stack.length > 0) {
        const scope = stack.pop();
        for (const variable of scope.variables) {
          allVariables.add(variable);
        }
        stack.push(...scope.childScopes);
      }
      walk(program, visitorKeys, (node) => {
        if (node.type === 'CallExpression') {
          callExpressions.push(node);
        }
        return false;
      });
    }

    /**
     * Propagates taint through assignments and function parameters until a
     * fixpoint is reached.
     */
    function propagateTaint() {
      let changed = true;
      while (changed) {
        changed = false;
        for (const variable of allVariables) {
          if (taintedVariables.has(variable)) {
            continue;
          }
          if (getAssignedExpressions(variable).some((expression) => isTaintedExpression(expression))) {
            taintedVariables.add(variable);
            changed = true;
          }
        }
        for (const call of callExpressions) {
          if (call.callee.type !== 'Identifier') {
            continue;
          }
          const calleeVariable = resolveVariable(call.callee);
          if (!calleeVariable) {
            continue;
          }
          for (const def of calleeVariable.defs) {
            const functionNode = def.type === 'FunctionName' ? def.node : def.node.init;
            if (!functionNode || (functionNode.type !== 'FunctionDeclaration' && functionNode.type !== 'FunctionExpression' && functionNode.type !== 'ArrowFunctionExpression')) {
              continue;
            }
            const functionScope = sourceCode.getScope ? sourceCode.getScope(functionNode) : null;
            if (!functionScope) {
              continue;
            }
            call.arguments.forEach((argument, index) => {
              const param = functionNode.params[index];
              if (!param || param.type !== 'Identifier' || !isTaintedExpression(argument)) {
                return;
              }
              const paramVariable = functionScope.set.get(param.name) || functionScope.variables.find((variable) => variable.name === param.name);
              if (paramVariable && !taintedVariables.has(paramVariable)) {
                taintedVariables.add(paramVariable);
                changed = true;
              }
            });
          }
        }
      }
    }

    //--------------------------------------------------------------------------
    // Sink checks
    //--------------------------------------------------------------------------

    /**
     * Checks whether a key variable is filtered against sensitive keys
     * anywhere inside the given root node.
     * @param {ASTNode} root The subtree to search.
     * @param {string} keyName The name of the key variable.
     * @returns {boolean} True when the key is filtered.
     */
    function isKeyFiltered(root, keyName) {
      return walk(root, visitorKeys, (node) => {
        if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.operator)) {
          const sides = [node.left, node.right];
          const hasKey = sides.some((side) => side.type === 'Identifier' && side.name === keyName);
          const hasSensitiveLiteral = sides.some((side) => side.type === 'Literal' && typeof side.value === 'string' && sensitiveKeys.includes(side.value));
          if (hasKey && hasSensitiveLiteral) {
            return true;
          }
        }
        if (
          node.type === 'CallExpression' &&
          node.callee.type === 'MemberExpression' &&
          node.callee.property.type === 'Identifier' &&
          ['includes', 'indexOf'].includes(node.callee.property.name) &&
          node.arguments.some((argument) => argument.type === 'Identifier' && argument.name === keyName) &&
          node.callee.object.type === 'ArrayExpression' &&
          node.callee.object.elements.some((element) => element && element.type === 'Literal' && sensitiveKeys.includes(element.value))
        ) {
          return true;
        }
        return false;
      });
    }

    /**
     * Finds the nearest enclosing function or program node.
     * @param {ASTNode} node The node to start from.
     * @returns {ASTNode} The enclosing function-like node.
     */
    function getEnclosingFunction(node) {
      let current = node;
      while (current.parent) {
        current = current.parent;
        if (/Function/.test(current.type) || current.type === 'Program') {
          return current;
        }
      }
      return current;
    }

    /**
     * Reports `Object.assign(target, tainted)` sinks.
     * @param {ASTNode} node The call expression to check.
     */
    function checkObjectAssign(node) {
      const callee = node.callee;
      if (
        callee.type !== 'MemberExpression' ||
        callee.object.type !== 'Identifier' ||
        callee.object.name !== 'Object' ||
        callee.property.type !== 'Identifier' ||
        callee.property.name !== 'assign' ||
        node.arguments.length < 2
      ) {
        return;
      }
      const target = node.arguments[0];
      if (isNullPrototypeObject(target)) {
        return;
      }
      for (const source of node.arguments.slice(1)) {
        if (isTaintedExpression(source)) {
          context.report({
            node: source,
            message: "Possible prototype pollution: attacker-controlled object passed to 'Object.assign'.",
          });
        }
      }
    }

    /**
     * Reports `target[key] = value` sinks where `key` enumerates the keys of
     * an attacker-controlled object.
     * @param {ASTNode} node The `for...in` / `for...of` statement to check.
     * @param {ASTNode} sourceExpression The expression whose keys are enumerated.
     */
    function checkKeyEnumeration(node, sourceExpression) {
      if (!isTaintedExpression(sourceExpression)) {
        return;
      }
      let keyName = null;
      if (node.left.type === 'VariableDeclaration' && node.left.declarations[0].id.type === 'Identifier') {
        keyName = node.left.declarations[0].id.name;
      } else if (node.left.type === 'Identifier') {
        keyName = node.left.name;
      }
      if (!keyName) {
        return;
      }
      const enclosingFunction = getEnclosingFunction(node);
      if (isKeyFiltered(enclosingFunction, keyName)) {
        return;
      }
      walk(node.body, visitorKeys, (child) => {
        if (
          child.type === 'AssignmentExpression' &&
          child.left.type === 'MemberExpression' &&
          child.left.computed &&
          child.left.property.type === 'Identifier' &&
          child.left.property.name === keyName &&
          !isNullPrototypeObject(child.left.object)
        ) {
          context.report({
            node: child.left,
            message: 'Possible prototype pollution: unfiltered key from attacker-controlled object used in computed assignment.',
          });
        }
        return false;
      });
    }

    return {
      'Program:exit'(program) {
        collectFacts(program);
        propagateTaint();
        walk(program, visitorKeys, (node) => {
          if (node.type === 'CallExpression') {
            checkObjectAssign(node);
          } else if (node.type === 'ForInStatement') {
            checkKeyEnumeration(node, node.right);
          } else if (
            node.type === 'ForOfStatement' &&
            node.right.type === 'CallExpression' &&
            node.right.callee.type === 'MemberExpression' &&
            node.right.callee.object.type === 'Identifier' &&
            node.right.callee.object.name === 'Object' &&
            node.right.callee.property.type === 'Identifier' &&
            node.right.callee.property.name === 'keys'
          ) {
            checkKeyEnumeration(node, node.right.arguments[0]);
          }
          return false;
        });
      },
    };
  },
};
