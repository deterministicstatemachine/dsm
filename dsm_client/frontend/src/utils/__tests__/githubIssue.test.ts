/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import {
  DSM_RELEASE_REPO,
  DSM_RELEASE_REPO_URL,
  BETA_BUG_TEMPLATE,
  BETA_FEATURE_TEMPLATE,
  BETA_FEEDBACK_TEMPLATE,
  buildGitHubIssueUrl,
} from '../githubIssue';

describe('exported constants', () => {
  test('DSM_RELEASE_REPO is a valid org/repo string', () => {
    expect(DSM_RELEASE_REPO).toBe('deterministicstatemachine/dsm');
  });

  test('DSM_RELEASE_REPO_URL points to GitHub', () => {
    expect(DSM_RELEASE_REPO_URL).toBe('https://github.com/deterministicstatemachine/dsm');
  });

  test('template constants are .yml filenames', () => {
    expect(BETA_BUG_TEMPLATE).toBe('bug-report-beta.yml');
    expect(BETA_FEATURE_TEMPLATE).toBe('feature-request-beta.yml');
    expect(BETA_FEEDBACK_TEMPLATE).toBe('general-feedback-beta.yml');
  });
});

describe('buildGitHubIssueUrl', () => {
  const BASE = 'https://github.com/deterministicstatemachine/dsm/issues/new';

  test('returns plain new-issue URL when called with no arguments', () => {
    expect(buildGitHubIssueUrl()).toBe(BASE);
  });

  test('returns plain new-issue URL for empty object', () => {
    expect(buildGitHubIssueUrl({})).toBe(BASE);
  });

  test('returns plain URL when all fields are empty/whitespace', () => {
    expect(buildGitHubIssueUrl({ title: '', body: '  ', template: undefined })).toBe(BASE);
  });

  test('includes template param', () => {
    const url = buildGitHubIssueUrl({ template: BETA_BUG_TEMPLATE });
    expect(url).toContain('template=bug-report-beta.yml');
    expect(url.startsWith(BASE + '?')).toBe(true);
  });

  test('includes title param', () => {
    const url = buildGitHubIssueUrl({ title: 'Test bug' });
    expect(url).toContain('title=Test+bug');
  });

  test('includes body param', () => {
    const url = buildGitHubIssueUrl({ body: 'Steps to reproduce' });
    expect(url).toContain('body=Steps+to+reproduce');
  });

  test('includes all params together', () => {
    const url = buildGitHubIssueUrl({
      title: 'Bug title',
      body: 'Bug body',
      template: BETA_FEATURE_TEMPLATE,
    });
    expect(url).toContain('template=feature-request-beta.yml');
    expect(url).toContain('title=Bug+title');
    expect(url).toContain('body=Bug+body');
  });

  test('trims title whitespace', () => {
    const url = buildGitHubIssueUrl({ title: '  spaced  ' });
    expect(url).toContain('title=spaced');
  });

  test('truncates body to 6000 characters', () => {
    const longBody = 'x'.repeat(7000);
    const url = buildGitHubIssueUrl({ body: longBody });
    const params = new URLSearchParams(url.split('?')[1]);
    expect(params.get('body')!.length).toBe(6000);
  });
});
