"""命令行端到端：固定锚、退出码、JSON 报告、DER 输入、排列不变性、8 张上限。"""

from __future__ import annotations

import itertools
import json
import subprocess
import sys

from x509verify.certutil import cert_sha256

from .certfactory import AT_TIME, SERVER_AUTH, issue, name_constraints, new_key
from .conftest import REPO_ROOT, run_cli


def _simple():
    rk, ik, lk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True, path_len=None)
    ica = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    return root, ica, leaf


def test_cli_accept_exit0_json(tmp_path):
    root, ica, leaf = _simple()
    rc, payload, err = run_cli(tmp_path, root, leaf, [ica],
                               "www.example.com", AT_TIME)
    assert rc == 0
    assert payload["trusted"] is True
    assert len(payload["path"]) == 3
    assert payload["path"][0]["sha256"] == cert_sha256(root)
    assert payload["path"][-1]["sha256"] == cert_sha256(leaf)
    assert payload["targetDns"] == "www.example.com"


def test_cli_reject_exit1(tmp_path):
    root, ica, leaf = _simple()
    rc, payload, err = run_cli(tmp_path, root, leaf, [ica],
                               "other.example.net", AT_TIME)
    assert rc == 1
    assert payload["trusted"] is False
    assert payload["candidateCount"] >= 1
    f0 = payload["candidatesFirstFailures"][0]
    assert {"sha256", "subject", "reason", "detail"} <= set(f0)


def test_cli_pin_mismatch_exit2(tmp_path):
    root, ica, leaf = _simple()
    wrong = "00" * 32
    anchor_p = tmp_path / "a.pem"
    from cryptography.hazmat.primitives import serialization
    anchor_p.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    server_p = tmp_path / "s.pem"
    server_p.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    int_p = tmp_path / "i.pem"
    int_p.write_bytes(ica.public_bytes(serialization.Encoding.PEM))
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(anchor_p), "--pin", wrong,
           "--server", str(server_p), "--intermediate", str(int_p),
           "--at-time", "2026-06-01T00:00:00Z",
           "--name", "www.example.com", "--json"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 2
    assert "锚固定值不符" in proc.stderr


def test_cli_pin_accepts_colon_and_uppercase(tmp_path):
    root, ica, leaf = _simple()
    digest = cert_sha256(root)
    colon = ":".join(digest[i:i + 2] for i in range(0, 64, 2)).upper()
    anchor_p = tmp_path / "a.pem"
    from cryptography.hazmat.primitives import serialization
    anchor_p.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    server_p = tmp_path / "s.pem"
    server_p.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    int_p = tmp_path / "i.pem"
    int_p.write_bytes(ica.public_bytes(serialization.Encoding.PEM))
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(anchor_p), "--pin", colon,
           "--server", str(server_p), "--intermediate", str(int_p),
           "--at-time", "2026-06-01T00:00:00Z",
           "--name", "www.example.com", "--json"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_cli_der_inputs(tmp_path):
    root, ica, leaf = _simple()
    from cryptography.hazmat.primitives import serialization
    a = tmp_path / "a.der"
    a.write_bytes(root.public_bytes(serialization.Encoding.DER))
    s = tmp_path / "s.der"
    s.write_bytes(leaf.public_bytes(serialization.Encoding.DER))
    i = tmp_path / "i.der"
    i.write_bytes(ica.public_bytes(serialization.Encoding.DER))
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(a), "--pin", cert_sha256(root),
           "--server", str(s), "--intermediate", str(i),
           "--at-time", "2026-06-01T00:00:00Z",
           "--name", "www.example.com", "--json"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_cli_concatenated_pem_intermediates(tmp_path):
    # 构造交叉双分支，把全部中间证书写进同一个串联 PEM 文件
    ra, rb, ka, lk = new_key(), new_key(), new_key(), new_key()
    root_a = issue(subject_cn="Root", subject_key=ra, is_ca=True)
    root_b = issue(subject_cn="Root", subject_key=rb, is_ca=True)
    ca_a = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root",
                 issuer_key=ra, is_ca=True, path_len=0)
    ca_b = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root",
                 issuer_key=rb, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA X",
                 issuer_key=ka, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    from cryptography.hazmat.primitives import serialization
    a = tmp_path / "a.pem"
    a.write_bytes(root_a.public_bytes(serialization.Encoding.PEM))
    s = tmp_path / "s.pem"
    s.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(
        ca_a.public_bytes(serialization.Encoding.PEM)
        + ca_b.public_bytes(serialization.Encoding.PEM)
        + root_b.public_bytes(serialization.Encoding.PEM)
    )
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(a), "--pin", cert_sha256(root_a),
           "--server", str(s), "--intermediate", str(bundle),
           "--at-time", "2026-06-01T00:00:00Z",
           "--name", "h.example.com", "--json"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["trusted"] is True


def test_cli_too_many_intermediates_exit2(tmp_path):
    root, ica, leaf = _simple()
    # 9 张互不相同的干扰中间证书 + 真 ica，去重后超过 8
    junk = []
    for _ in range(9):
        k = new_key()
        junk.append(issue(subject_cn="Junk", subject_key=k, issuer_cn="Nowhere",
                          issuer_key=new_key(), is_ca=True))
    rc, payload, err = run_cli(tmp_path, root, leaf, junk + [ica],
                               "www.example.com", AT_TIME)
    assert rc == 2
    assert "上限 8" in err


def test_cli_permutation_invariant_end_to_end(tmp_path):
    # 嵌套 + 交叉混合，多种输入排列下退出码与路径摘要必须一致
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True, path_len=3,
                 nc=name_constraints(permitted=(".example.com",)))
    k1, k2, k2b, k3, lk = (new_key() for _ in range(5))
    ca1 = issue(subject_cn="CA1", subject_key=k1, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=2)
    ca2 = issue(subject_cn="CA2", subject_key=k2, issuer_cn="CA1",
                issuer_key=k1, is_ca=True, path_len=1,
                nc=name_constraints(permitted=(".a.example.com",)))
    ca2_alt = issue(subject_cn="CA2", subject_key=k2b, issuer_cn="CA1",
                    issuer_key=k1, is_ca=True, path_len=1,
                    nc=name_constraints(excluded=(".a.example.com",)))
    ca3 = issue(subject_cn="CA3", subject_key=k3, issuer_cn="CA2",
                issuer_key=k2, is_ca=True, path_len=0)
    leaf = issue(subject_cn="leaf", subject_key=lk, issuer_cn="CA3",
                 issuer_key=k3, is_ca=False,
                 san_dns=("host.a.example.com",), eku=[SERVER_AUTH])
    pool = [ca1, ca2, ca2_alt, ca3]

    outcomes = set()
    paths = set()
    for order in itertools.permutations(pool):
        rc, payload, err = run_cli(tmp_path, root, leaf, list(order),
                                   "host.a.example.com", AT_TIME)
        outcomes.add(rc)
        assert rc == 0, err
        paths.add(tuple(n["sha256"] for n in payload["path"]))
    assert outcomes == {0}
    assert paths == {tuple(cert_sha256(c) for c in (root, ca1, ca2, ca3, leaf))}


def test_cli_human_readable_output(tmp_path):
    root, ica, leaf = _simple()
    from cryptography.hazmat.primitives import serialization
    a = tmp_path / "a.pem"
    a.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    s = tmp_path / "s.pem"
    s.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    i = tmp_path / "i.pem"
    i.write_bytes(ica.public_bytes(serialization.Encoding.PEM))
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(a), "--pin", cert_sha256(root),
           "--server", str(s), "--intermediate", str(i),
           "--at-time", "2026-06-01T00:00:00Z",
           "--name", "www.example.com"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "结论: 接受" in proc.stdout
    assert cert_sha256(root) in proc.stdout


def test_cli_unparseable_time_exit2(tmp_path):
    root, ica, leaf = _simple()
    rc, payload, err = run_cli(tmp_path, root, leaf, [ica],
                               "www.example.com", AT_TIME,
                               extra_args=())
    # 直接构造坏时刻
    from cryptography.hazmat.primitives import serialization
    a = tmp_path / "a2.pem"
    a.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    s = tmp_path / "s2.pem"
    s.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    i = tmp_path / "i2.pem"
    i.write_bytes(ica.public_bytes(serialization.Encoding.PEM))
    cmd = [sys.executable, "-m", "x509verify",
           "--anchor", str(a), "--pin", cert_sha256(root),
           "--server", str(s), "--intermediate", str(i),
           "--at-time", "not-a-time", "--name", "www.example.com"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 2
