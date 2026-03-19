// SPDX-License-Identifier: Apache-2.0

export const DSM_RELEASE_REPO = 'DSM-Deterministic-State-Machine/deterministic-state-machine';
export const DSM_RELEASE_REPO_URL = `https://github.com/${DSM_RELEASE_REPO}`;

type GitHubIssueInput = {
  title?: string;
  body?: string;
};

export function buildGitHubIssueUrl(input: GitHubIssueInput = {}): string {
  const title = (input.title || '').trim();
  const body = (input.body || '').trim().slice(0, 6000);

  if (!title && !body) {
    return `${DSM_RELEASE_REPO_URL}/issues/new`;
  }

  const params = new URLSearchParams();
  if (title) params.set('title', title);
  if (body) params.set('body', body);
  return `${DSM_RELEASE_REPO_URL}/issues/new?${params.toString()}`;
}
