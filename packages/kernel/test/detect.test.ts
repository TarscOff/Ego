import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRemote } from '../src/project/detect.ts';

test('remote parsing: GitHub, GitLab, Azure DevOps (dev.azure.com and legacy visualstudio.com)', () => {
  assert.equal(parseRemote('origin', 'git@github.com:acme/demo.git').path, 'acme/demo');
  assert.equal(parseRemote('origin', 'https://gitlab.com/group/sub/proj.git').provider, 'gitlab');
  assert.equal(parseRemote('origin', 'https://dev.azure.com/org/proj/_git/repo').path, 'org/proj/repo');
  assert.equal(parseRemote('origin', 'git@ssh.dev.azure.com:v3/org/proj/repo').path, 'org/proj/repo');
  assert.equal(
    parseRemote('origin', 'https://acme.visualstudio.com/Project/_git/repo').path,
    'acme/Project/repo',
  );
  assert.equal(
    parseRemote('origin', 'https://acme.visualstudio.com/DefaultCollection/Project/_git/repo').path,
    'acme/Project/repo',
  );
  assert.equal(
    parseRemote('origin', 'https://acme@acme.visualstudio.com/Project/_git/repo').path,
    'acme/Project/repo',
  );
});
