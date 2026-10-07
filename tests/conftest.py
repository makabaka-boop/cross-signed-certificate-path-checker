"""测试共享助手：直接驱动 build_candidates 与 CLI。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization

from x509verify.chain import build_candidates
from x509verify.certutil import cert_sha256
from x509verify.profiles import check_static_profile

from .certfactory import AT_TIME

REPO_ROOT = Path(__file__).resolve().parent.parent


def evaluate(anchor, ee, intermediates, target_dns, at_time=AT_TIME):
    """返回 (candidates, valid_digests)，valid_digests 为合法链摘要元组列表。"""
    check_static_profile(anchor, "anchor")
    check_static_profile(ee, "ee")
    for i, c in enumerate(intermediates):
        check_static_profile(c, f"int[{i}]")
    candidates = build_candidates(anchor, ee, list(intermediates),
                                  target_dns, at_time)
    valid = [c.digest_tuple() for c in candidates if c.valid]
    return candidates, valid


def reasons(candidates):
    return [c.failure.reason for c in candidates if c.failure is not None]


def run_cli(tmp_path, anchor, ee, intermediates, target_dns, at_time,
            extra_args=()):
    anchor_p = tmp_path / "anchor.pem"
    anchor_p.write_bytes(anchor.public_bytes(serialization.Encoding.PEM))
    server_p = tmp_path / "server.pem"
    server_p.write_bytes(ee.public_bytes(serialization.Encoding.PEM))
    inter_paths = []
    for i, c in enumerate(intermediates):
        p = tmp_path / f"int{i}.pem"
        p.write_bytes(c.public_bytes(serialization.Encoding.PEM))
        inter_paths.append(p)

    cmd = [
        sys.executable, "-m", "x509verify",
        "--anchor", str(anchor_p),
        "--pin", cert_sha256(anchor),
        "--server", str(server_p),
        "--at-time", at_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--name", target_dns,
        "--json",
    ]
    for p in inter_paths:
        cmd += ["--intermediate", str(p)]
    cmd += list(extra_args)

    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    payload = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, payload, proc.stderr


@pytest.fixture
def cli():
    return run_cli
