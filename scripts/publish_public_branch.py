"""Point the history-free publication branch at the current commit's tree.

The branch holds exactly one parentless commit whose tree is the source
commit's tree, so it can be pushed without the development history. Only
committed content is published; the working tree and index are not read.
"""
import argparse
import subprocess
import sys


def git(*args, stdin=None):
    result = subprocess.run(["git", *args], input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--branch", default="main", help="publication branch (default: main)")
    parser.add_argument("--source", default="HEAD", help="commit whose tree is published (default: HEAD)")
    parser.add_argument("--message", help="commit message (default: the branch's current message, else 'Initial commit')")
    args = parser.parse_args()

    tree = git("rev-parse", f"{args.source}^{{tree}}")
    current = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{args.branch}"],
                             capture_output=True, text=True).stdout.strip()
    if current and git("rev-parse", f"{current}^{{tree}}") == tree:
        print(f"{args.branch} already publishes {tree}")
        return
    message = args.message or (git("log", "-1", "--format=%B", current) if current else "Initial commit")
    commit = git("commit-tree", tree, stdin=message + "\n")
    git("update-ref", f"refs/heads/{args.branch}", commit, *([current] if current else []))
    print(f"{args.branch} -> {commit[:12]} (tree {tree[:12]}, no parents)")


if __name__ == "__main__":
    main()
