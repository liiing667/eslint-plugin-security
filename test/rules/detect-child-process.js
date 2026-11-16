'use strict';

const RuleTester = require('eslint').RuleTester;
const tester = new RuleTester();

const ruleName = 'detect-child-process';
const rule = require(`../../rules/${ruleName}`);

tester.run(ruleName, rule, {
  valid: [
    "child_process.exec('ls')",
    `
    var {} = require('child_process');
    var result = /hello/.exec(str);`,
    `
    var {} = require('node:child_process');
    var result = /hello/.exec(str);`,
    `
    import {} from 'child_process';
    var result = /hello/.exec(str);`,
    `
    import {} from 'node:child_process';
    var result = /hello/.exec(str);`,
    "var { spawn } = require('child_process'); spawn(str);",
    "var { spawn } = require('node:child_process'); spawn(str);",
    "import { spawn } from 'child_process'; spawn(str);",
    "import { spawn } from 'node:child_process'; spawn(str);",
    `
    var foo = require('child_process');
    function fn () {
      var foo = /hello/;
      var result = foo.exec(str);
    }`,
    "var child = require('child_process'); child.spawn(str)",
    "var child = require('node:child_process'); child.spawn(str)",
    "import child from 'child_process'; child.spawn(str)",
    "import child from 'node:child_process'; child.spawn(str)",
    `
    var foo = require('child_process');
    function fn () {
      var result = foo.spawn(str);
    }`,
    "require('child_process').spawn(str)",
    `
    function fn () {
      require('child_process').spawn(str)
    }`,
    `
    var child_process = require('child_process');
    var FOO = 'ls';
    child_process.exec(FOO);`,
    `
    import child_process from 'child_process';
    const FOO = 'ls';
    child_process.exec(FOO);`,
    `
    var cp = require('node:child_process');
    cp.execSync('ls -la');`,
    `
    const { execSync } = require('child_process');
    execSync('ls ' + '-la');`,
    `
    const { execSync: runSync } = require('node:child_process');
    runSync('ls');`,
    `
    var child = require('child_process');
    child.execSync(CMD);
    const CMD = 'ls';`,
    `
    import { execSync } from 'child_process';
    execSync(\`ls \${DIR}\`);
    const DIR = '/tmp';`,
    "var { spawn } = require('child_process'); spawn(str, { shell: false });",
    "var child = require('child_process'); child.spawn('ls', ['-la'], { shell: false });",
    "var child = require('node:child_process'); child.spawn('ls', { shell: 0 });",
    "var child = require('child_process'); child.spawn('ls', ['-la']);",
    `
    const { execFile } = require('child_process');
    execFile('ls', ['-la'], { shell: false });`,
    `
    var cp = require('node:child_process');
    cp.spawn('ls ' + cmd, { shell: false });`,
    `
    var cp = require('child_process');
    cp.spawn(\`ls \${DIR}\`);
    const DIR = '/tmp';`,
    `
    var cp = require('child_process');
    cp.execFile('ls', args, { shell: false });`,
  ],
  invalid: [
    {
      code: "require('child_process')",
      errors: [{ message: 'Found require("child_process")' }],
    },
    {
      code: "require('node:child_process')",
      errors: [{ message: 'Found require("node:child_process")' }],
    },
    {
      code: "var child = require('child_process'); child.exec(com)",
      errors: [{ message: 'Found child_process.exec() with non Literal first argument' }],
    },
    {
      code: "var child = require('node:child_process'); child.exec(com)",
      errors: [{ message: 'Found child_process.exec() with non Literal first argument' }],
    },
    {
      code: "import child from 'child_process'; child.exec(com)",
      errors: [{ message: 'Found child_process.exec() with non Literal first argument' }],
    },
    {
      code: "import child from 'node:child_process'; child.exec(com)",
      errors: [{ message: 'Found child_process.exec() with non Literal first argument' }],
    },
    {
      code: "var child = sinon.stub(require('child_process')); child.exec.returns({});",
      errors: [{ message: 'Found require("child_process")' }],
    },
    {
      code: "var child = sinon.stub(require('node:child_process')); child.exec.returns({});",
      errors: [{ message: 'Found require("node:child_process")' }],
    },
    {
      code: `
      var foo = require('child_process');
      function fn () {
        var result = foo.exec(str);
      }`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 4 }],
    },
    {
      code: `
      import foo from 'child_process';
      function fn () {
        var result = foo.exec(str);
      }`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 4 }],
    },
    {
      code: `
      import foo from 'node:child_process';
      function fn () {
        var result = foo.exec(str);
      }`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 4 }],
    },
    {
      code: `
      require('child_process').exec(str)`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 2 }],
    },
    {
      code: `
      function fn () {
        require('child_process').exec(str)
      }`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 3 }],
    },
    {
      code: `
      const {exec} = require('child_process');
      exec(str)`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 3 }],
    },
    {
      code: `
      const {exec} = require('node:child_process');
      exec(str)`,
      errors: [{ message: 'Found child_process.exec() with non Literal first argument', line: 3 }],
    },
    {
      code: "var child = require('child_process'); child.execSync(req.body.cmd)",
      errors: [{ message: 'Found child_process.execSync() with non Literal first argument' }],
    },
    {
      code: "var child = require('node:child_process'); child.execSync(com)",
      errors: [{ message: 'Found child_process.execSync() with non Literal first argument' }],
    },
    {
      code: `
      const { execSync } = require('child_process');
      execSync(req.body.cmd)`,
      errors: [{ message: 'Found child_process.execSync() with non Literal first argument', line: 3 }],
    },
    {
      code: `
      const { execSync: runSync } = require('node:child_process');
      runSync(cmd)`,
      errors: [{ message: 'Found child_process.execSync() with non Literal first argument', line: 3 }],
    },
    {
      code: `
      import { execSync } from 'child_process';
      execSync(userInput)`,
      errors: [{ message: 'Found child_process.execSync() with non Literal first argument', line: 3 }],
    },
    {
      code: "var cp = require('child_process'); cp.spawn('ls ' + userInput, { shell: true })",
      errors: [{ message: 'Found child_process.spawn() with non Literal first argument and shell enabled' }],
    },
    {
      code: "var cp = require('node:child_process'); cp.spawnSync(cmd, { shell: true })",
      errors: [{ message: 'Found child_process.spawnSync() with non Literal first argument and shell enabled' }],
    },
    {
      code: `
      const { spawn } = require('child_process');
      spawn(\`ls \${userInput}\`, { shell: true })`,
      errors: [{ message: 'Found child_process.spawn() with non Literal first argument and shell enabled', line: 3 }],
    },
    {
      code: "var cp = require('child_process'); cp.execFile(userInput, ['-la'], { shell: true })",
      errors: [{ message: 'Found child_process.execFile() with non Literal first argument and shell enabled' }],
    },
    {
      code: "var cp = require('node:child_process'); cp.execFileSync(cmd, args, { shell: '/bin/sh' })",
      errors: [{ message: 'Found child_process.execFileSync() with non Literal first argument and shell enabled' }],
    },
    {
      code: `
      var cp = require('child_process');
      cp.spawn(userInput, { shell: shellPath })`,
      errors: [{ message: 'Found child_process.spawn() with non Literal first argument and shell enabled', line: 3 }],
    },
  ],
});
