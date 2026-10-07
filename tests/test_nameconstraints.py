"""嵌套名称约束：permitted 交集、excluded 累计、中间层 SAN 也受约束。"""

from __future__ import annotations

import itertools

from x509verify.certutil import cert_sha256

from .certfactory import SERVER_AUTH, issue, name_constraints, new_key
from .conftest import evaluate, reasons


def _chain_with_constraints(root_nc=None, ca_nc=None,
                            int_san=(), leaf_name="host.a.example.com"):
    rk, ik, lk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 path_len=1, nc=root_nc)
    ica = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0,
                san_dns=int_san, nc=ca_nc)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False, san_dns=(leaf_name,),
                 eku=[SERVER_AUTH])
    return root, ica, leaf


def test_nested_permitted_intersection_accept():
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        ca_nc=name_constraints(permitted=(".a.example.com",)),
    )
    _, valid = evaluate(root, leaf, [ica], "host.a.example.com")
    assert len(valid) == 1


def test_nested_permitted_intersection_leaf_outside():
    # root 允许 example.com，CA 只允许 a.example.com；叶子在 b.example.com
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        ca_nc=name_constraints(permitted=(".a.example.com",)),
        leaf_name="host.b.example.com",
    )
    cands, valid = evaluate(root, leaf, [ica], "host.b.example.com")
    assert valid == []
    assert "nameConstraints_permitted" in reasons(cands)


def test_excluded_subtree_blocks_deep_name():
    root, ica, leaf = _chain_with_constraints(
        ca_nc=name_constraints(excluded=(".b.example.com",)),
        leaf_name="x.b.example.com",
    )
    cands, valid = evaluate(root, leaf, [ica], "x.b.example.com")
    assert valid == []
    assert "nameConstraints_excluded" in reasons(cands)


def test_permitted_base_name_matches_apex():
    # ".example.com" 形式同时覆盖顶点 example.com
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        leaf_name="example.com",
    )
    _, valid = evaluate(root, leaf, [ica], "example.com")
    assert len(valid) == 1


def test_permitted_does_not_match_sibling_suffix():
    # ".example.com" 不得匹配 notexample.com（防止裸后缀拼接）
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        leaf_name="notexample.com",
    )
    cands, valid = evaluate(root, leaf, [ica], "notexample.com")
    assert valid == []
    assert "nameConstraints_permitted" in reasons(cands)


def test_non_dotted_constraint_exact_only():
    # 无点形式 "example.com" 只匹配精确同名，不匹配子域
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=("example.com",)),
        leaf_name="host.example.com",
    )
    cands, valid = evaluate(root, leaf, [ica], "host.example.com")
    assert valid == []


def test_intermediate_san_must_also_satisfy_constraints():
    # 中间 CA 自己带 SAN（如交叉场景的内部名），该 SAN 也要满足上层约束
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        int_san=("ca.other.org",),
    )
    cands, valid = evaluate(root, leaf, [ica], "host.a.example.com")
    assert valid == []
    f = cands[0].failure
    assert f.reason == "nameConstraints_permitted"
    assert f.sha256 == cert_sha256(ica)


def test_cumulative_permitted_and_excluded():
    # root: permitted .example.com；CA: permitted .a.example.com +
    # excluded x.a.example.com —— 累计交集后 x.a.example.com 必须被拒
    root, ica, leaf = _chain_with_constraints(
        root_nc=name_constraints(permitted=(".example.com",)),
        ca_nc=name_constraints(
            permitted=(".a.example.com",), excluded=("x.a.example.com",)),
        leaf_name="x.a.example.com",
    )
    cands, valid = evaluate(root, leaf, [ica], "x.a.example.com")
    assert valid == []
    assert "nameConstraints_excluded" in reasons(cands)


def test_constraint_per_candidate_independent_no_leak():
    """坏分支的 excluded 不得泄漏到同名 CA 的好分支上（核心安全性质）。

    rootA 签的 CA 带 excluded=.example.com；rootB 签的同名同钥 CA 无约束。
    锚固定 rootB 时 leaf 必须通过，尽管枚举过程中也走过 rootA 的坏分支。
    """
    ra, rb = new_key(), new_key()
    root_a = issue(subject_cn="Root", subject_key=ra, is_ca=True)
    root_b = issue(subject_cn="Root", subject_key=rb, is_ca=True)
    ka, lk = new_key(), new_key()
    ca_bad = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root",
                   issuer_key=ra, is_ca=True, path_len=0,
                   nc=name_constraints(excluded=(".example.com",)))
    ca_good = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root",
                    issuer_key=rb, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA X",
                 issuer_key=ka, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    for order in itertools.permutations([ca_bad, ca_good, root_a]):
        cands, valid = evaluate(root_b, leaf, list(order), "www.example.com")
        assert len(valid) == 1
        assert valid[0] == tuple(
            cert_sha256(c) for c in (root_b, ca_good, leaf))
        # 坏分支作为断头/另接 root_a 的候选存在，但其失败原因不该是“接 root_b”
        anchored_b = [c for c in cands if c.reaches_anchor and
                      ca_bad in c.chain]
        assert anchored_b == []  # ca_bad 不可能接到 root_b
