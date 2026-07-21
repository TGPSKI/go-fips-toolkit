#!/usr/bin/env bash
set -euo pipefail

# clone.sh — Clone Go repositories for FIPS crypto audit
#
# Usage:
#   ./audit/clone.sh repos.txt                # Clone repos listed in file (one per line)
#   ./audit/clone.sh -r org/repo1 org/repo2   # Clone specific repos
#
# repos.txt format (one GitHub org/repo per line, # comments allowed):
#   myorg/my-service
#   myorg/my-library
#   # kubernetes/kubernetes
#
# Environment:
#   REPOS_DIR     Override clone destination (default: ./repos)
#   BRANCH        Override branch to clone (default: try main, then master)
#   DEPTH         Clone depth (default: 1 for shallow clone, 0 for full)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOS_DIR="${REPOS_DIR:-$PROJECT_DIR/repos}"
DEPTH="${DEPTH:-1}"

DEFAULT_REPOS=()

REPOS=()

parse_args() {
  if [[ $# -eq 0 ]]; then
    if [[ ${#DEFAULT_REPOS[@]} -eq 0 ]]; then
      echo "Usage: $0 repos.txt" >&2
      echo "       $0 -r org/repo1 org/repo2" >&2
      echo "" >&2
      echo "No default repos configured. Pass a repos.txt file or use -r." >&2
      exit 1
    fi
    REPOS=("${DEFAULT_REPOS[@]}")
    return
  fi

  if [[ "$1" == "-r" ]]; then
    shift
    REPOS=("$@")
    return
  fi

  if [[ -f "$1" ]]; then
    while IFS= read -r line; do
      line="${line%%#*}"  # strip comments
      line="${line// /}"  # strip whitespace
      [[ -n "$line" ]] && REPOS+=("$line")
    done < "$1"
    return
  fi

  echo "ERROR: $1 is not a file. Use -r for inline repos or pass a repos.txt file." >&2
  exit 1
}

clone_repo() {
  local repo="$1"
  local name="${repo#*/}"
  local dest="$REPOS_DIR/$name"

  if [[ -d "$dest/.git" ]]; then
    echo "==> $name already cloned, pulling latest..."
    git -C "$dest" pull --ff-only 2>/dev/null || echo "    (pull failed, using existing)"
    return 0
  fi

  local depth_flag=()
  [[ "$DEPTH" -gt 0 ]] && depth_flag=(--depth "$DEPTH")

  local branches=("${BRANCH:-main}" "master")
  [[ -n "${BRANCH:-}" ]] && branches=("$BRANCH")

  for branch in "${branches[@]}"; do
    echo "==> Cloning $repo (branch: $branch)..."
    if git clone "${depth_flag[@]}" --branch "$branch" "https://github.com/$repo.git" "$dest" 2>/dev/null; then
      echo "    Cloned on branch: $branch"
      return 0
    fi
    rm -rf "$dest"
  done

  echo "    ERROR: could not clone $repo" >&2
  return 1
}

main() {
  parse_args "$@"
  mkdir -p "$REPOS_DIR"

  local failed=0
  for repo in "${REPOS[@]}"; do
    clone_repo "$repo" || ((failed++))
  done

  echo ""
  echo "==> ${#REPOS[@]} repos processed, $failed failed"
  echo "    Location: $REPOS_DIR"
  ls -1 "$REPOS_DIR"

  return $failed
}

main "$@"
