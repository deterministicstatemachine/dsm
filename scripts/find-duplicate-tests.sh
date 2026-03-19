#!/usr/bin/env bash
# find-duplicate-tests.sh
# Simple helper, finds files where both .test.ts and .test.tsx exist for the same basename

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "Searching for duplicate test basenames in: $ROOT"

# find files ending in .test.ts or .test.tsx, print their basenames
while IFS= read -r file; do
  name=$(basename "$file")
  base=${name%.test.*}
  ext=${name##*.}
  printf "%s\t%s\t%s\n" "$base" "$ext" "$file"
done < <(find "$ROOT" -type f \( -name "*.test.ts" -or -name "*.test.tsx" \) -not -path "*/node_modules/*" -not -path "*/target/*" -not -path "*/dist/*" | sort) \
  | awk -F"\t" '{ arr[$1] = arr[$1] "\n" $2 "\t" $3 } END { for (i in arr) { n = split(arr[i], a, "\n"); if (n>2) print i ":" arr[i] } }' \
  | sed 's/^/DUPLICATE: /' || true

echo "Done. To remove duplicates, pick the .ts or .tsx file to keep and delete the other(s)."
