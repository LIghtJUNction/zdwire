#!/usr/bin/env python3
"""Prepare and publish a verified zdwire release using Python's standard library."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
LOCKS = ("Cargo.lock", "comparison/Cargo.lock", "fuzz/Cargo.lock")


def run(*args, check=True, input_text=None):
    return subprocess.run(args, check=check, input=input_text, text=True, capture_output=True)


def git(*args):
    return run("git", *args).stdout.strip()


def package_version(text):
    package = tomllib.loads(text)["package"]
    if package["name"] != "zdwire" or not VERSION.fullmatch(package["version"]):
        raise ValueError("expected zdwire with a stable x.y.z version")
    return package["version"]


def bump_version(version, bump):
    if not VERSION.fullmatch(version):
        raise ValueError("version must be stable x.y.z")
    parts = list(map(int, version.split(".")))
    if bump == "current":
        return version
    if bump not in ("major", "minor", "patch"):
        raise ValueError("bump must be major, minor, patch, or current")
    index = {"major": 0, "minor": 1, "patch": 2}[bump]
    parts[index] += 1
    for pos in range(index + 1, 3):
        parts[pos] = 0
    return ".".join(map(str, parts))


def replace_package_version(text, version):
    old = package_version(text)
    # Restrict the edit to [package], leaving dependency versions untouched.
    section = re.search(r"(?ms)^\[package\]\s*\n.*?(?=^\[|\Z)", text)
    if section is None:
        raise ValueError("missing [package]")
    content, count = re.subn(
        r'(?m)^(version\s*=\s*")' + re.escape(old) + r'("\s*)$',
        lambda match: match[1] + version + match[2],
        section[0],
    )
    if count != 1:
        raise ValueError("expected one package version assignment")
    return text[:section.start()] + content + text[section.end():]


def replace_lock_version(text, old, version):
    packages = tomllib.loads(text)["package"]
    matching = [p for p in packages if p["name"] == "zdwire"]
    if len(matching) != 1 or matching[0]["version"] != old:
        raise ValueError("lockfile must contain exactly the current zdwire version")
    changed, count = re.subn(
        r'(\[\[package\]\]\s*\nname = "zdwire"\s*\nversion = ")'
        + re.escape(old) + r'(")',
        lambda match: match[1] + version + match[2],
        text,
    )
    if count != 1:
        raise ValueError("unexpected zdwire lockfile entry")
    return changed


def default_branch(event):
    branch = event["repository"]["default_branch"]
    run("git", "check-ref-format", "--branch", branch)
    return branch


def fetch_default(branch):
    git("fetch", "--no-tags", "origin", "+refs/heads/" + branch
        + ":refs/remotes/origin/" + branch)
    return "refs/remotes/origin/" + branch


def require_ancestor(commit, base):
    if run("git", "merge-base", "--is-ancestor", commit, base, check=False).returncode:
        raise ValueError("release commit is outside the default branch history")


def candidate(commit):
    version = package_version(git("show", commit + ":Cargo.toml"))
    return {"sha": commit, "version": version, "tag": "v" + version}


def prepare(event_name, event, ref, bump, run_id):
    branch = default_branch(event)
    if event_name == "workflow_dispatch":
        if ref != "refs/heads/" + branch:
            raise ValueError("manual releases must run on the default branch")
        if not re.fullmatch(r"[0-9]+", run_id):
            raise ValueError("invalid GitHub run id")
        bump_version("0.0.0", bump)  # Validate before changing the checkout.
    elif event_name == "release":
        release = event["release"]
        tag = release["tag_name"]
        if (event.get("action") != "published" or release.get("draft")
                or release.get("prerelease") or not tag.startswith("v")
                or not VERSION.fullmatch(tag[1:]) or ref != "refs/tags/" + tag):
            raise ValueError("expected a published stable version tag")
    elif event_name == "push":
        if ref != "refs/heads/" + branch:
            raise ValueError("push releases must originate on the default branch")
        if not re.fullmatch(r"[0-9]+", run_id):
            raise ValueError("invalid GitHub run id")
        bump_version("0.0.0", bump)  # Validate before changing the checkout.
    else:
        raise ValueError("unsupported release event")

    base = fetch_default(branch)
    if event_name == "release":
        git("fetch", "origin", "refs/tags/" + tag + ":refs/tags/" + tag)
        commit = git("rev-parse", "refs/tags/" + tag + "^{commit}")
        require_ancestor(commit, base)
        result = candidate(commit)
        if result["tag"] != tag:
            raise ValueError("tag does not match Cargo.toml")
        return result

    # A rerun of a failed dispatch resumes its original candidate.
    previous = git("log", base, "-1", "--format=%H", "--extended-regexp",
                   "--grep=^Zdwire-Release-Run: " + run_id + "$")
    if previous:
        return candidate(previous)

    git("checkout", "--detach", base)
    old = package_version(Path("Cargo.toml").read_text())
    version = bump_version(old, bump)
    if old != version:
        manifest = Path("Cargo.toml")
        manifest.write_text(replace_package_version(manifest.read_text(), version))
        files = ["Cargo.toml"]
        for filename in LOCKS:
            path = Path(filename)
            if path.is_file():
                path.write_text(replace_lock_version(path.read_text(), old, version))
                files.append(filename)
        git("config", "user.name", "github-actions[bot]")
        git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git("add", "--", *files)
        git("commit", "-m", "chore: release " + version,
            "-m", "Zdwire-Release-Run: " + run_id)
        # A regular push refuses concurrent changes; no force update is used.
        git("push", "origin", "HEAD:refs/heads/" + branch)
    return candidate(git("rev-parse", "HEAD"))


def request_json(url, token=None, data=None):
    headers = {"Accept": "application/json", "User-Agent": "zdwire-release/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    encoded = None
    if data is not None:
        encoded = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=encoded, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        # Error bodies and authorization data are deliberately not logged.
        raise RuntimeError("release API returned HTTP " + str(error.code)) from None


def registry_published(version):
    value = request_json("https://crates.io/api/v1/crates/zdwire/" + version)
    if value is None:
        return False
    published = value.get("version", {})
    if published.get("crate") != "zdwire" or published.get("num") != version:
        raise RuntimeError("unexpected crates.io version response")
    return True


def publish(event, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or git("rev-parse", "HEAD") != sha:
        raise ValueError("publish checkout does not match the tested commit")
    require_ancestor(sha, fetch_default(default_branch(event)))
    result = candidate(sha)
    tag = result["tag"]
    repository = event["repository"]["full_name"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    github_token = os.environ.get("GH_TOKEN")
    if not github_token:
        raise ValueError("GH_TOKEN is required")
    remote_tag = git("ls-remote", "--tags", "origin", "refs/tags/" + tag)
    if remote_tag:
        git("fetch", "origin", "refs/tags/" + tag + ":refs/tags/" + tag)
        if git("rev-parse", "refs/tags/" + tag + "^{commit}") != sha:
            raise ValueError("version tag already points at a different commit")
    else:
        git("config", "user.name", "github-actions[bot]")
        git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git("tag", "-a", tag, sha, "-m", "zdwire " + result["version"])
        git("push", "origin", "refs/tags/" + tag)

    if registry_published(result["version"]):
        print("crates.io already contains " + result["version"] + "; upload skipped")
    else:
        if not os.environ.get("CARGO_REGISTRY_TOKEN"):
            raise ValueError("CARGO_REGISTRY_TOKEN secret is required")
        # Cargo receives the secret only through its documented environment variable.
        process = subprocess.run(["cargo", "publish", "--locked"], check=False)
        if process.returncode and not registry_published(result["version"]):
            raise RuntimeError("cargo publish failed; rerun this workflow to resume")

    endpoint = "https://api.github.com/repos/" + repository + "/releases"
    release = request_json(endpoint + "/tags/" + tag, github_token)
    if release is None:
        release = request_json(endpoint, github_token, {
            "tag_name": tag, "target_commitish": sha,
            "name": "zdwire " + result["version"],
            "generate_release_notes": True, "draft": False, "prerelease": False,
        })
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("existing GitHub release must be published and stable")
    print(release["html_url"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "publish"))
    parser.add_argument("--sha")
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if args.command == "prepare":
        result = prepare(os.environ["GITHUB_EVENT_NAME"], event,
                         os.environ["GITHUB_REF"], os.environ.get("INPUT_BUMP", "current"),
                         os.environ["GITHUB_RUN_ID"])
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            for key, value in result.items():
                output.write(key + "=" + value + "\n")
        print("Release candidate " + result["tag"] + " at " + result["sha"])
    else:
        publish(event, args.sha or "")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        # Do not echo subprocess arguments or captured network output with credentials.
        message = str(error) if not isinstance(error, subprocess.CalledProcessError) else "git command failed"
        print("release: " + message, file=sys.stderr)
        sys.exit(1)
