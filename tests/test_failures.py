"""候选失败报告与签名完整性补充测试。"""

from __future__ import annotations

from x509verify.certutil import cert_sha256

from .certfactory import SERVER_AUTH, issue, name_constraints, new_key
from .conftest import evaluate


def test_each_candidate_first_failure_is_distinct_and_local():
    """两条接锚候选在不同证书上首次失败，报告必须分别定位到那张证书。"""
    ra, rb = new_key(), new_key()
    root_a = issue(subject_cn="Root A", subject_key=ra, is_ca=True)
    root_b = issue(subject_cn="Root B", subject_key=rb, is_ca=True)
    ka, kb, lk = new_key(), new_key(), new_key()
    # 分支 A：CA 自身直接排除 example.com（leaf 在 NC 上失败）
    ca_a = issue(subject_cn="CA", subject_key=ka, issuer_cn="Root A",
                 issuer_key=ra, is_ca=True, path_len=0,
                 nc=name_constraints(excluded=(".example.com",)))
    # 分支 B：CA 无 NC，但根本不是 CA（去掉 BC）——在 CA 层失败
    ca_b = issue(subject_cn="CA", subject_key=kb, issuer_cn="Root B",
                 issuer_key=rb, is_ca=True, path_len=0,
                 include_bc=False, include_ku=False)
    leaf_a = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                   issuer_key=ka, is_ca=False, san_dns=("h.example.com",),
                   eku=[SERVER_AUTH])
    # leaf_b 用 kb 签，SAN 相同
    leaf_b = issue(subject_cn="h2", subject_key=lk, issuer_cn="CA",
                   issuer_key=kb, is_ca=False, san_dns=("h.example.com",),
                   eku=[SERVER_AUTH])

    # 注意 leaf_a/leaf_b 是不同证书；这里把两张 leaf 都放进池不适用
    # 单 EE 模型——分别评估，确认报告定位准确：
    cands_a, valid_a = evaluate(root_a, leaf_a, [ca_a], "h.example.com")
    assert valid_a == []
    f = cands_a[0].failure
    assert f.sha256 == cert_sha256(leaf_a)
    assert f.reason == "nameConstraints_excluded"

    cands_b, valid_b = evaluate(root_b, leaf_b, [ca_b], "h.example.com")
    assert valid_b == []
    f = cands_b[0].failure
    assert f.sha256 == cert_sha256(ca_b)
    assert f.reason == "notCA"


def test_excluded_constraint_two_levels_above_reaches_ee():
    """排除约束在锚上施加，中间层再收窄 permitted，累计后仍在 EE 生效。"""
    rk, ik, lk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 path_len=1, nc=name_constraints(
                     permitted=(".example.com",),
                     excluded=("blocked.example.com",)))
    ica = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0,
                nc=name_constraints(permitted=(".example.com",)))
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False,
                 san_dns=("blocked.example.com",), eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, [ica], "blocked.example.com")
    assert valid == []
    assert cands[0].failure.reason == "nameConstraints_excluded"


def test_tampered_intermediate_signature_does_not_build_chain():
    """直接改写中间证书 DER 中的一个字节后，验签必失败、链不成立。

    这里用“重签时换成无关密钥”的等价方式（certfactory），
    模拟签名与 TBS 不匹配；单张验签是唯一的建链门槛。
    """
    rk, ik, lk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    good_ca = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                    issuer_key=rk, is_ca=True, path_len=0)
    # 同主体/同公钥，但用第三把钥签——任何用 rk 或 ik 的验证都过不了
    rogue_key = new_key()
    rogue_ca = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root",
                     issuer_key=rogue_key, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])

    cands, valid = evaluate(root, leaf, [rogue_ca], "h.example.com")
    assert valid == []
    assert all(not c.reaches_anchor for c in cands)

    # 好 CA 一进池，合法链立即成立，证明枚举不受 rogue 影响
    _, valid = evaluate(root, leaf, [rogue_ca, good_ca], "h.example.com")
    assert len(valid) == 1
    assert cert_sha256(good_ca) in valid[0]


def test_anchor_key_cannot_sign_forgeable_name():
    """另一主体名（哪怕字节相似）的证书不能终止于锚——名字必须逐字节相同。"""
    rk, ik, lk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    # CA 的发行者名写成 "Root "（尾随空格），锚主体名是 "Root"
    ica = issue(subject_cn="CA", subject_key=ik, issuer_cn="Root ",
                issuer_key=rk, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="CA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, [ica], "h.example.com")
    assert valid == []
    # 即便签名是锚的钥签的，发行者名字节不同也接不上锚
    assert all(not c.reaches_anchor for c in cands)
