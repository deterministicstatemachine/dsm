// SPDX-License-Identifier: Apache-2.0

export const DSM_RELEASE_REPO = 'deterministicstatemachine/dsm';
export const DSM_RELEASE_REPO_URL = `https://github.com/${DSM_RELEASE_REPO}`;

export const BETA_BUG_TEMPLATE = 'bug-report-beta.yml';
export const BETA_FEATURE_TEMPLATE = 'feature-request-beta.yml';
export const BETA_FEEDBACK_TEMPLATE = 'general-feedback-beta.yml';

export type GitHubIssueTemplate =
  | typeof BETA_BUG_TEMPLATE
  | typeof BETA_FEATURE_TEMPLATE
  | typeof BETA_FEEDBACK_TEMPLATE;

type GitHubIssueInput = {
  title?: string;
  body?: string;
  template?: GitHubIssueTemplate;
};

export function buildGitHubIssueUrl(input: GitHubIssueInput = {}): string {
  const title = (input.title || '').trim();
  const body = (input.body || '').trim().slice(0, 6000);
  const template = input.template;

  if (!title && !body && !template) {
    return `${DSM_RELEASE_REPO_URL}/issues/new`;
  }

  const params = new URLSearchParams();
  if (template) params.set('template', template);
  if (title) params.set('title', title);
  if (body) params.set('body', body);
  return `${DSM_RELEASE_REPO_URL}/issues/new?${params.toString()}`;
}
