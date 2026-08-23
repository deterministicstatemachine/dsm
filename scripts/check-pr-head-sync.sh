#!/usr/bin/env bash
# Refuse to merge a PR whose head is not the branch tip you think it is.
#
# A push can land on the remote branch ref while GitHub's pull-request object
# stays pinned to the previous head. The window is silent, `git push` reports
# success, and `gh pr merge` merges whatever the PR object points at — so the
# stale commit lands on main and the PR description advertises changes that are
# not in it. This happened twice: #698 (merged the head before the review fixes)
# and #700 (same, one review round later), each costing a corrective PR.
#
# The check is three SHAs and nothing else:
#
#   local HEAD  ==  remote branch tip  ==  pulls/N.head.sha
#
# Deliberately NOT in scope: merging, branch cleanup, policy override, check
# status. This is a precondition, not a workflow. Run it, then merge yourself.
#
# COMPANION RULE — admin merges.
#   An admin merge is a SEPARATE authorization event and is never inferred from
#   prior merge authorization. If branch protection blocks a merge, permission
#   to merge is not permission to bypass the policy that blocked it: ask, naming
#   the policy being overridden and why waiting is unacceptable. Authorization to
#   merge a specific PR — including "merge it even if it's not green" — does not
#   carry to `--admin`.
#
# Usage:
#   ./scripts/check-pr-head-sync.sh <pr-number> [--repo owner/name]
#
# Exit codes:
#   0  all three agree — safe to merge
#   1  mismatch — DO NOT MERGE
#   2  usage or environment error (not a verdict)

set -euo pipefail

die_env() { printf '%s\n' "check-pr-head-sync: $*" >&2; exit 2; }

PR=""
REPO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:-}"; shift 2 || die_env "--repo needs a value" ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die_env "unknown flag: $1" ;;
    *) [ -z "$PR" ] || die_env "expected one PR number, got extra arg: $1"; PR="$1"; shift ;;
  esac
done

[ -n "$PR" ] || die_env "usage: $0 <pr-number> [--repo owner/name]"
case "$PR" in (*[!0-9]*|"") die_env "PR must be a number, got: $PR" ;; esac
command -v gh >/dev/null 2>&1 || die_env "gh CLI not found"
git rev-parse --git-dir >/dev/null 2>&1 || die_env "not inside a git repository"

if [ -z "$REPO" ]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)" \
    || die_env "could not determine repo; pass --repo owner/name"
fi

LOCAL_HEAD="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" != "HEAD" ] || die_env "detached HEAD; check out the PR branch first"

# The PR object: its head SHA and the branch it claims to be tracking.
PR_JSON="$(gh api "repos/$REPO/pulls/$PR" --jq '.head.sha + " " + .head.ref')" \
  || die_env "could not read PR #$PR from $REPO"
PR_HEAD="${PR_JSON%% *}"
PR_REF="${PR_JSON##* }"

if [ "$PR_REF" != "$BRANCH" ]; then
  die_env "checked out '$BRANCH' but PR #$PR tracks '$PR_REF' — wrong branch for this PR"
fi

# The remote branch ref, read from the server rather than from a local
# remote-tracking ref, which may itself be stale.
REMOTE_TIP="$(gh api "repos/$REPO/git/ref/heads/$BRANCH" --jq '.object.sha')" \
  || die_env "could not read remote ref heads/$BRANCH from $REPO"

if [ "$LOCAL_HEAD" = "$REMOTE_TIP" ] && [ "$LOCAL_HEAD" = "$PR_HEAD" ]; then
  printf 'check-pr-head-sync: OK — PR #%s head, remote tip and local HEAD all at %s\n' \
    "$PR" "${LOCAL_HEAD:0:12}"
  exit 0
fi

cat >&2 <<EOF

  ############################################################
  #  DO NOT MERGE PR #$PR — head SHAs disagree                
  ############################################################

    local HEAD        ${LOCAL_HEAD:0:12}  (branch $BRANCH)
    remote branch tip ${REMOTE_TIP:0:12}
    PR object head    ${PR_HEAD:0:12}   <-- this is what a merge would take

EOF

if [ "$LOCAL_HEAD" = "$REMOTE_TIP" ] && [ "$REMOTE_TIP" != "$PR_HEAD" ]; then
  cat >&2 <<'EOF'
  The push landed but the PR object has not caught up. Merging now would take
  the STALE commit and land it on the base branch, while the PR description
  advertises changes that are not in it.

  Wait and re-run. If it does not converge, recover the same way #699 and #701
  did: fresh branch from the base, cherry-pick the missing commit, new PR.
EOF
elif [ "$LOCAL_HEAD" != "$REMOTE_TIP" ]; then
  cat >&2 <<'EOF'
  Local HEAD is not the remote tip. Push first (or fetch, if someone else
  pushed), then re-run. Do not merge on the assumption that your local work is
  what the PR contains.
EOF
fi

printf '\n' >&2
exit 1
