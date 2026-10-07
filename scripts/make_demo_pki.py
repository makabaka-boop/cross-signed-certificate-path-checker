#!/usr/bin/env python3
"""生成离线演示用 PKI（不联网）：

场景 A（demo/cross/）——同名 CA 不同密钥的交叉签发：
    root-a / root-b 同名 "Shared Root"、不同密钥（DER 不同）；
    ca-under-a：被 root-a 签，名称约束排除整个 .example.com（坏分支）；
    ca-under-b：同主体、同公钥、不同 DER，被 root-b 签且无约束（好分支）；
    leaf 由该 CA 公钥签出，SAN=www.example.com。
    固定锚 root-b 时接受（好分支）；固定锚 root-a 时拒绝（坏分支 NC）。
    另有 leaf-other，SAN=other.example.net，在两把锚下都接受。

场景 B（demo/rollover/）——self-issued 换钥：
    root：旧钥自签锚；rollover：同名 self-issued、新公钥、旧钥签名；
    ica 由新钥签发；leaf 由 ica 签发。
"""

from __future__ import annotations

import pathlib
import sys

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tests"))

from certfactory import SERVER_AUTH, issue, name_constraints, new_key  # noqa: E402
from x509verify.certutil import cert_sha256  # noqa: E402


def write_pem(path: pathlib.Path, cert) -> str:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_sha256(cert)


def main() -> None:
    root_dir = pathlib.Path(__file__).resolve().parent.parent / "demo"

    # ---------------- 场景 A：交叉签发 ----------------
    cross = root_dir / "cross"
    cross.mkdir(parents=True, exist_ok=True)

    ka, kb = new_key(), new_key()
    root_a = issue(subject_cn="Shared Root", subject_key=ka, is_ca=True)
    root_b = issue(subject_cn="Shared Root", subject_key=kb, is_ca=True)

    ck = new_key()
    ca_under_a = issue(
        subject_cn="Edge CA", subject_key=ck, issuer_cn="Shared Root",
        issuer_key=ka, is_ca=True, path_len=0,
        nc=name_constraints(excluded=(".example.com",)),
    )
    ca_under_b = issue(
        subject_cn="Edge CA", subject_key=ck, issuer_cn="Shared Root",
        issuer_key=kb, is_ca=True, path_len=0,
    )

    lk = new_key()
    leaf = issue(subject_cn="www.example.com", subject_key=lk,
                 issuer_cn="Edge CA", issuer_key=ck, is_ca=False,
                 san_dns=("www.example.com",), eku=[SERVER_AUTH])
    lk2 = new_key()
    leaf_other = issue(subject_cn="other.example.net", subject_key=lk2,
                       issuer_cn="Edge CA", issuer_key=ck, is_ca=False,
                       san_dns=("other.example.net",), eku=[SERVER_AUTH])

    digests_a = {}
    digests_a["root-a.pem"] = write_pem(cross / "root-a.pem", root_a)
    digests_a["root-b.pem"] = write_pem(cross / "root-b.pem", root_b)
    write_pem(cross / "ca-under-a.pem", ca_under_a)
    write_pem(cross / "ca-under-b.pem", ca_under_b)
    write_pem(cross / "leaf-example.pem", leaf)
    write_pem(cross / "leaf-other.pem", leaf_other)

    # 无序中间证书大礼包：两张交叉 CA + 另一把根（干扰项，不得被当作锚）
    (cross / "intermediates.pem").write_bytes(
        ca_under_a.public_bytes(serialization.Encoding.PEM)
        + ca_under_b.public_bytes(serialization.Encoding.PEM)
        + root_a.public_bytes(serialization.Encoding.PEM)
    )

    # ---------------- 场景 B：self-issued 换钥 ----------------
    ro = root_dir / "rollover"
    ro.mkdir(parents=True, exist_ok=True)

    old_k = new_key()
    root = issue(subject_cn="Rollover Root", subject_key=old_k, is_ca=True,
                 path_len=1)
    new_k = new_key()
    rollover = issue(subject_cn="Rollover Root", subject_key=new_k,
                     issuer_cn="Rollover Root", issuer_key=old_k,
                     is_ca=True, path_len=None)
    ik, lk3 = new_key(), new_key()
    ica = issue(subject_cn="Post-rollover ICA", subject_key=ik,
                issuer_cn="Rollover Root", issuer_key=new_k,
                is_ca=True, path_len=0)
    leaf_r = issue(subject_cn="svc.example.org", subject_key=lk3,
                   issuer_cn="Post-rollover ICA", issuer_key=ik,
                   is_ca=False, san_dns=("svc.example.org",),
                   eku=[SERVER_AUTH])

    digests_b = {}
    digests_b["root.pem"] = write_pem(ro / "root.pem", root)
    write_pem(ro / "rollover-self-issued.pem", rollover)
    write_pem(ro / "ica.pem", ica)
    write_pem(ro / "leaf.pem", leaf_r)

    # ---------------- 摘要清单 ----------------
    manifest = [
        "# 演示信任锚 DER 摘要（SHA-256，小写十六进制）",
        "# 用 --pin 固定；锚文件本身即使被替换，摘要不符即退出码 2。",
        "",
        "[cross]",
        f"root-a.pem = {digests_a['root-a.pem']}",
        f"root-b.pem = {digests_a['root-b.pem']}",
        "",
        "[rollover]",
        f"root.pem   = {digests_b['root.pem']}",
        "",
    ]
    (root_dir / "pins.txt").write_text("\n".join(manifest), encoding="utf-8")
    print("\n".join(manifest))


if __name__ == "__main__":
    main()
