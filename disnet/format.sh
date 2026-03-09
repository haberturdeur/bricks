#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v clang-format >/dev/null 2>&1; then
    echo "clang-format not found in PATH" >&2
    exit 1
fi

mapfile -t files < <(
    git ls-files \
        'disnet/*.cpp' \
        'disnet/include/**/*.hpp' \
        'disnet/example/**/*.cpp' \
        'disnet/test_apps/**/*.cpp' \
        'disnet/tests/**/*.cpp'
)

if ((${#files[@]} == 0)); then
    exit 0
fi

existing=()
for file in "${files[@]}"; do
    [[ -f "$file" ]] && existing+=("$file")
done

if ((${#existing[@]} == 0)); then
    exit 0
fi

clang-format -i "${existing[@]}"
echo "Formatted ${#existing[@]} file(s)."
