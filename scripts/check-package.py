#!/usr/bin/env python3
"""Verify that zdwire's published package has no dependency or build-script escape."""
import json
from pathlib import Path
import subprocess
import tomllib

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"], text=True))
root = next(package for package in metadata["packages"] if package["name"] == "zdwire")
assert root["dependencies"] == [], "zdwire must have no dependencies of any kind"
assert not Path("build.rs").exists(), "build.rs is prohibited"
manifest = tomllib.loads(Path("Cargo.toml").read_text())
assert manifest["package"].get("build", False) is False, "custom build scripts are prohibited"
assert manifest["package"]["rust-version"] == "1.99.1", "update the MSRV matrix with the manifest"
source = Path("src/lib.rs").read_text()
assert "#![no_std]" in source, "the crate must always be no_std"
assert "#![forbid(unsafe_code)]" in source, "keep the safe-Rust audit guarantee"
print("Dependency, build script, MSRV, no_std, and safe-Rust contract verified")
