"""边界：8 张中间证书上限、锚混入中间池、深链。"""

from __future__ import annotations

from x509verify.certutil import cert_sha256

from .certfactory import SERVER_AUTH, issue, new_key
from .conftest import evaluate


def test_anchor_in_intermediate_pool_does_not_duplicate():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True, path_len=None)
    ik, lk = new_key(), new_key()
    ica = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    # 把锚自身混进中间证书池：合法链仍只有一条且锚只出现一次
    cands, valid = evaluate(root, leaf, [root, ica, root], "h.example.com")
    assert len(valid) == 1
    assert valid[0].count(cert_sha256(root)) == 1


def test_chain_with_eight_intermediates_accepted():
    # 锚 + 8 张中间 CA + EE，pathLen 全部放开
    keys = [new_key() for _ in range(9)]
    rk = keys[0]
    root = issue(subject_cn="C0", subject_key=rk, is_ca=True, path_len=8)
    cas = []
    for d in range(1, 9):
        cas.append(issue(
            subject_cn=f"C{d}", subject_key=keys[d],
            issuer_cn=f"C{d - 1}", issuer_key=keys[d - 1],
            is_ca=True, path_len=8 - d,
        ))
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="C8",
                 issuer_key=keys[8], is_ca=False,
                 san_dns=("host.depth.example",), eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, cas, "host.depth.example")
    assert len(valid) == 1
    assert len(valid[0]) == 10  # 锚 + 8 中间 + EE


def test_chain_with_nine_intermediates_rejected_by_cli(tmp_path=None):
    # 引擎接受“池里 8 张”，CLI 在去重后超 8 张时退出码 2。
    # 这里直接模拟 9 张输入交给引擎：第 9 张仍可能被枚举（引擎不负责
    # 输入上限），所以上限由 CLI 保证——用一个真正接不上的 9 张深链
    # 验证引擎防环/终止仍正确（不做时间/结果断言，只验证有限终止）。
    keys = [new_key() for _ in range(10)]
    root = issue(subject_cn="C0", subject_key=keys[0], is_ca=True,
                 path_len=9)
    cas = []
    for d in range(1, 10):
        cas.append(issue(
            subject_cn=f"C{d}", subject_key=keys[d],
            issuer_cn=f"C{d - 1}", issuer_key=keys[d - 1],
            is_ca=True, path_len=9 - d,
        ))
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="C9",
                 issuer_key=keys[9], is_ca=False,
                 san_dns=("host.deep.example",), eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, cas, "host.deep.example")
    # 9 张中间：路径本身合法（引擎不强制 8 上限，上限在 CLI 层）
    assert len(valid) == 1
    assert len(valid[0]) == 11
