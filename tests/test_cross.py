"""同名 CA、不同密钥与交叉签发：核心是“不能遇到第一张发行者就停下”。"""

from __future__ import annotations

import itertools

from x509verify.certutil import cert_sha256

from .certfactory import SERVER_AUTH, issue, name_constraints, new_key
from .conftest import evaluate


def test_same_name_cas_distinct_keys():
    """两张同名 "Shared CA"、不同密钥；leaf 只被其中一张签出。

    若建链时只按名字取第一张就会把合法链误拒（或把坏分支当全部分支）。
    """
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ka, kb = new_key(), new_key()
    ca_good = issue(subject_cn="Shared CA", subject_key=ka, issuer_cn="Root",
                    issuer_key=rk, is_ca=True, path_len=0)
    ca_other = issue(subject_cn="Shared CA", subject_key=kb, issuer_cn="Root",
                     issuer_key=rk, is_ca=True, path_len=0)
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="Shared CA",
                 issuer_key=ka, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])

    for order in itertools.permutations([ca_good, ca_other]):
        cands, valid = evaluate(root, leaf, list(order), "h.example.com")
        assert len(valid) == 1
        assert tuple(cert_sha256(c) for c in (root, ca_good, leaf)) == valid[0]


def test_backtracking_first_issuer_bad():
    """经典“第一张发行者是坏分支”：同名 CA 被两把不同根交叉签发。

    rootA 签的 CA(a 钥) 受到排除全部 example.com 的名称约束（坏分支）；
    rootB 签的同主体 CA(a 钥) 无约束（好分支）。信任锚固定为 rootA。
    若枚举停在第一张同名发行者（rootB 那版），会漏接锚；正确实现要把
    两条交叉链都枚举出来，并最终拒绝，因为固定锚是 rootA 且坏分支才接它。

    另再测锚固定为 rootB 时必须接受好分支，且坏分支的 NC 不会泄漏过去。
    """
    ra, rb = new_key(), new_key()
    root_a = issue(subject_cn="Shared Root", subject_key=ra, is_ca=True)
    root_b = issue(subject_cn="Shared Root", subject_key=rb, is_ca=True)
    ka = new_key()
    # 同主体、同公钥（都是 ka），两张不同 DER 的 CA 证书
    ca_under_a = issue(
        subject_cn="X CA", subject_key=ka, issuer_cn="Shared Root",
        issuer_key=ra, is_ca=True, path_len=0,
        nc=name_constraints(excluded=(".example.com",)),
    )
    ca_under_b = issue(
        subject_cn="X CA", subject_key=ka, issuer_cn="Shared Root",
        issuer_key=rb, is_ca=True, path_len=0,
    )
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="X CA",
                 issuer_key=ka, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])

    pool = [ca_under_a, ca_under_b, root_b]  # root_b 放进无序中间证书里也不许被当锚

    # 锚=rootA：只有坏分支接锚，必须拒绝，失败在 leaf 的 NC 排除
    cands, valid = evaluate(root_a, leaf, pool, "h.example.com")
    assert valid == []
    anchored = [c for c in cands if c.reaches_anchor]
    assert len(anchored) == 1
    f = anchored[0].failure
    assert f is not None and f.reason == "nameConstraints_excluded"
    assert f.sha256 == cert_sha256(leaf)

    # 锚=rootB：好分支接锚，必须接受；坏分支/断头路径不影响结论
    cands, valid = evaluate(root_b, leaf, [ca_under_a, ca_under_b, root_a],
                            "h.example.com")
    assert len(valid) == 1
    assert valid[0] == tuple(cert_sha256(c) for c in (root_b, ca_under_b, leaf))


def test_cross_signed_both_branches_valid_unique_display_path():
    """两条交叉链都合法时，按 DER 摘要序列选出唯一展示路径，且与输入顺序无关。"""
    ra, rb, ka, lk = new_key(), new_key(), new_key(), new_key()
    root_a = issue(subject_cn="Root A", subject_key=ra, is_ca=True)
    root_b = issue(subject_cn="Root B", subject_key=rb, is_ca=True)
    # 交叉证书：CA 钥 ka，分别被两把根签（这里同主体 CA 名也同名）
    ca_a = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root A",
                 issuer_key=ra, is_ca=True, path_len=0)
    ca_b = issue(subject_cn="CA X", subject_key=ka, issuer_cn="Root B",
                 issuer_key=rb, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA X",
                 issuer_key=ka, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])

    # 把两把根都放进候选池；锚轮流固定
    for anchor, good_ca in ((root_a, ca_a), (root_b, ca_b)):
        other_root = root_b if anchor is root_a else root_a
        for order in itertools.permutations([ca_a, ca_b, other_root]):
            cands, valid = evaluate(anchor, leaf, list(order), "h.example.com")
            assert len(valid) == 1
            assert valid[0] == tuple(
                cert_sha256(c) for c in (anchor, good_ca, leaf))


def test_two_roots_in_pool_other_root_not_trusted():
    """中间证书池里混入另一把同名自签根，不得据此终止链。"""
    r1, r2 = new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=r1, is_ca=True)
    imposter = issue(subject_cn="Root", subject_key=r2, is_ca=True)  # 自签
    ik, lk = new_key(), new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=r1, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, [imposter, ica], "h.example.com")
    assert len(valid) == 1


def test_certificate_cycle_does_not_hang():
    """两张中间 CA 互签成环；DFS 必须终止且不把环上的证书重复计入。"""
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ka, kb = new_key(), new_key()
    # 先造两张互签证书：需要两步，先各拿一个占位版本再重签
    ca_a_by_root = issue(subject_cn="CA A", subject_key=ka, issuer_cn="Root",
                         issuer_key=rk, is_ca=True, path_len=1)
    ca_b_by_a = issue(subject_cn="CA B", subject_key=kb, issuer_cn="CA A",
                      issuer_key=ka, is_ca=True, path_len=0)
    # 环边：A 反过来声称由 B 签发（同名 A、同钥 ka，但 issuer=B、用 kb 签）
    ca_a_by_b = issue(subject_cn="CA A", subject_key=ka, issuer_cn="CA B",
                      issuer_key=kb, is_ca=True, path_len=0)
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA B",
                 issuer_key=kb, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    pool = [ca_a_by_root, ca_b_by_a, ca_a_by_b]
    cands, valid = evaluate(root, leaf, pool, "h.example.com")
    # 好链 root -> A(root签) -> B(A签) -> leaf 存在
    assert len(valid) == 1
    # 同一条 DER 序列不允许出现重复候选
    keys = [c.digest_tuple() for c in cands]
    assert len(keys) == len(set(keys))


def test_permutation_invariant_cross_scenario():
    """交叉复杂拓扑下，8 张以内所有排列给出完全一致的信任结论与展示路径。"""
    rk, kx, ky, kz = new_key(), new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True, path_len=3)
    x1 = issue(subject_cn="X", subject_key=kx, issuer_cn="Root",
               issuer_key=rk, is_ca=True, path_len=2)
    # 同名 X 的第二把钥版本（被 root 签，但 leaf 不由它签）——纯干扰
    kx2 = new_key()
    x2 = issue(subject_cn="X", subject_key=kx2, issuer_cn="Root",
               issuer_key=rk, is_ca=True, path_len=2)
    y = issue(subject_cn="Y", subject_key=ky, issuer_cn="X",
              issuer_key=kx, is_ca=True, path_len=1)
    # Y 的交叉版本：声称由 X2 签（坏分支，名字链走不到 leaf）
    y_alt = issue(subject_cn="Y", subject_key=ky, issuer_cn="X",
                  issuer_key=kx2, is_ca=True, path_len=1)
    z = issue(subject_cn="Z", subject_key=kz, issuer_cn="Y",
              issuer_key=ky, is_ca=True, path_len=0)
    lk = new_key()
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="Z",
                 issuer_key=kz, is_ca=False, san_dns=("host.example.net",),
                 eku=[SERVER_AUTH])
    pool = [x1, x2, y, y_alt, z]

    # 拓扑里其实有两条都合法的交叉链：
    #   root -> x1 -> y     -> z -> leaf
    #   root -> x2 -> y_alt -> z -> leaf
    # 正确实现应都枚举到；这里检验所有排列给出完全相同的合法链集合。
    seen = None
    for order in itertools.permutations(pool):
        _, valid = evaluate(root, leaf, list(order), "host.example.net")
        assert len(valid) == 2
        frozen = frozenset(valid)
        if seen is None:
            seen = frozen
        else:
            assert frozen == seen
