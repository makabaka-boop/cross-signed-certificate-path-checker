"""self-issued 换钥节点（RFC 5280 4.2.1.9 / 6.1）。

self-issued: subject 名 == issuer 名，但可能由*另一把同名密钥*签出，
这是 CA 换钥（rollover）的标准形态。它：
  * 不是 self-signed，不能因此被当作可信根；
  * 必须继续向上找到真正签它的锚；
  * 计算 pathLen 时不占中间 CA 名额（按 RFC 自签豁免口径，
    这里统一按 self-issued 豁免）。
"""

from __future__ import annotations

import datetime

from x509verify.certutil import cert_sha256

from .certfactory import AT_TIME, SERVER_AUTH, issue, new_key
from .conftest import evaluate, reasons


def test_key_rollover_valid_chain():
    """old-root 锚 -> rollover(self-issued, 由旧钥签) -> new 钥之下的 ICA -> leaf。"""
    old_k = new_key()
    anchor = issue(subject_cn="Root", subject_key=old_k, is_ca=True,
                   path_len=1)
    new_k = new_key()
    # 换钥证书：主体/发行者名都叫 "Root"，公钥是 new_k，但签名用 old_k
    rollover = issue(subject_cn="Root", subject_key=new_k,
                     issuer_cn="Root", issuer_key=old_k,
                     is_ca=True, path_len=None)
    ik, lk = new_key(), new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=new_k, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(anchor, leaf, [rollover, ica], "h.example.com")
    assert len(valid) == 1
    assert valid[0] == tuple(
        cert_sha256(c) for c in (anchor, rollover, ica, leaf))


def test_key_rollover_does_not_consume_pathlen_slot():
    """锚 pathLen=1：其下有两个中间节点（换钥 + ICA），其中只有 ICA 是非
    self-issued CA。换钥节点占名额的朴素实现会数到 2 而拒绝；按 RFC 口径
    豁免 self-issued 后应通过。对照组：把锚降到 pathLen=0 必须失败。"""
    def build(anchor_path_len):
        old_k = new_key()
        anchor = issue(subject_cn="Root", subject_key=old_k, is_ca=True,
                       path_len=anchor_path_len)
        new_k = new_key()
        rollover = issue(subject_cn="Root", subject_key=new_k,
                         issuer_cn="Root", issuer_key=old_k,
                         is_ca=True, path_len=None)
        ik, lk = new_key(), new_key()
        ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                    issuer_key=new_k, is_ca=True, path_len=0)
        leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                     issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                     eku=[SERVER_AUTH])
        return anchor, [rollover, ica], leaf

    anchor, pool, leaf = build(anchor_path_len=1)
    _, valid = evaluate(anchor, leaf, pool, "h.example.com")
    assert len(valid) == 1

    anchor0, pool0, leaf0 = build(anchor_path_len=0)
    cands, valid = evaluate(anchor0, leaf0, pool0, "h.example.com")
    assert valid == []
    assert "pathLenExceeded" in reasons(cands)


def test_unanchored_self_issued_not_treated_as_trusted_root():
    """没有锚签发的 self-issued 换钥证书必须拒绝（不能当自签根）。"""
    old_k, new_k, ik, lk = new_key(), new_key(), new_key(), new_key()
    # 锚是另一把同名的完全不同的密钥，不参与签发
    unrelated_anchor = issue(subject_cn="Root", subject_key=new_key(),
                             is_ca=True)
    # rollover 由 old_k 签 new_k，与锚的公钥对不上
    rollover = issue(subject_cn="Root", subject_key=new_k,
                     issuer_cn="Root", issuer_key=old_k,
                     is_ca=True, path_len=0)
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=new_k, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(unrelated_anchor, leaf, [rollover, ica],
                            "h.example.com")
    assert valid == []
    # 至少有一条断头路径结束在 rollover（self-issued 且无锚）
    reasons_seen = reasons(cands)
    assert "untrustedSelfIssued" in reasons_seen or "issuerNotFound" in reasons_seen
    assert all(not c.reaches_anchor for c in cands)


def test_self_issued_wrong_key_signature_rejected():
    """self-issued 节点若两张同名钥都签不动它（内容被篡改），不得接入。"""
    old_k, new_k = new_key(), new_key()
    anchor = issue(subject_cn="Root", subject_key=old_k, is_ca=True,
                   path_len=1)
    # 正确换钥证书
    good = issue(subject_cn="Root", subject_key=new_k,
                 issuer_cn="Root", issuer_key=old_k,
                 is_ca=True, path_len=None)
    # 同名同公钥但内容不同（serial/有效期）且由无关密钥签——验签必失败
    tampered = issue(
        subject_cn="Root", subject_key=new_k,
        issuer_cn="Root", issuer_key=new_key(),  # 第三把钥
        is_ca=True, path_len=0,
        not_before=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
    )
    ik, lk = new_key(), new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=new_k, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    # good 在池中：合法链成立；tampered 不会成为发行者
    _, valid = evaluate(anchor, leaf, [good, tampered, ica],
                        "h.example.com")
    assert len(valid) == 1

    # 拿走 good：只剩 tampered，接不上锚
    cands, valid = evaluate(anchor, leaf, [tampered, ica],
                            "h.example.com")
    assert valid == []


def test_rollover_node_itself_expired_rejected():
    """换钥节点也要过有效期（锚自身才豁免）。"""
    old_k, new_k = new_key(), new_key()
    anchor = issue(subject_cn="Root", subject_key=old_k, is_ca=True,
                   path_len=0)
    rollover = issue(
        subject_cn="Root", subject_key=new_k,
        issuer_cn="Root", issuer_key=old_k, is_ca=True, path_len=0,
        not_before=datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc),
    )
    ik, lk = new_key(), new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=new_k, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=lk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(anchor, leaf, [rollover, ica],
                            "h.example.com", at_time=AT_TIME)
    assert valid == []
    assert "notYetValid" in reasons(cands)
