"""基础链与单项语义测试。"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from x509verify.errors import ProfileError
from x509verify.profiles import check_static_profile

from .certfactory import (
    AT_TIME,
    ANY_EKU,
    CLIENT_AUTH,
    DEFAULT_NB,
    DEFAULT_NA,
    SERVER_AUTH,
    cn,
    issue,
    new_key,
)
from .conftest import evaluate, reasons, run_cli


def _simple_hierarchy(root_kw=None, ica_kw=None, leaf_kw=None):
    root_kw, ica_kw, leaf_kw = root_kw or {}, ica_kw or {}, leaf_kw or {}
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 path_len=None, **root_kw)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, **ica_kw)
    sk = new_key()
    leaf_defaults = dict(
        subject_cn="h", subject_key=sk, issuer_cn="ICA", issuer_key=ik,
        is_ca=False, san_dns=("www.example.com",), eku=[SERVER_AUTH],
    )
    leaf_defaults.update(leaf_kw)
    leaf = issue(**leaf_defaults)
    return root, ica, leaf


def test_basic_chain_valid():
    root, ica, leaf = _simple_hierarchy()
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert len(valid) == 1
    assert valid[0] == tuple(
        __import__("x509verify.certutil", fromlist=["cert_sha256"]).cert_sha256(c)
        for c in (root, ica, leaf)
    )


def test_missing_intermediate_rejected():
    root, ica, leaf = _simple_hierarchy()
    cands, valid = evaluate(root, leaf, [], "www.example.com")
    assert valid == []
    assert "issuerNotFound" in reasons(cands)


def test_wrong_dns_name_rejected():
    root, ica, leaf = _simple_hierarchy()
    cands, valid = evaluate(root, leaf, [ica], "evil.example.com")
    assert valid == []
    assert "nameMismatch" in reasons(cands)


def test_case_insensitive_exact_dns():
    root, ica, leaf = _simple_hierarchy()
    _, valid = evaluate(root, leaf, [ica], "WWW.Example.COM")
    assert len(valid) == 1


def test_expired_intermediate():
    root, ica, leaf = _simple_hierarchy(ica_kw=dict(
        not_after=datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)))
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert valid == []
    assert "expired" in reasons(cands)


def test_not_yet_valid_ee():
    root, ica, leaf = _simple_hierarchy(leaf_kw=dict(
        not_before=datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)))
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert valid == []
    assert "notYetValid" in reasons(cands)


def test_validity_boundaries_inclusive():
    root, ica, leaf = _simple_hierarchy(leaf_kw=dict(
        not_before=DEFAULT_NB, not_after=DEFAULT_NA))
    assert evaluate(root, leaf, [ica], "www.example.com",
                    DEFAULT_NB)[1]
    assert evaluate(root, leaf, [ica], "www.example.com",
                    DEFAULT_NA)[1]


def test_intermediate_not_ca_rejected():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    fake_ca = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                    issuer_key=rk, is_ca=False,
                    san_dns=("ica.example.com",), eku=[SERVER_AUTH])
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, [fake_ca], "www.example.com")
    assert valid == []
    assert "notCA" in reasons(cands)


def test_ca_without_key_cert_sign_rejected():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    bad_ca = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                   issuer_key=rk, is_ca=True, include_ku=False)
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    cands, valid = evaluate(root, leaf, [bad_ca], "www.example.com")
    assert valid == []
    assert "missingKeyUsage" in reasons(cands)


# ---------------- EKU 传播 ----------------

def test_ee_without_eku_rejected():
    root, ica, leaf = _simple_hierarchy(leaf_kw=dict(eku=None))
    # factory 默认 eku=None 表示不加 EKU
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert valid == []
    assert "ekuRequired" in reasons(cands)


def test_ee_client_auth_only_rejected():
    root, ica, leaf = _simple_hierarchy(leaf_kw=dict(eku=[CLIENT_AUTH]))
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert valid == []
    assert "ekuServerAuth" in reasons(cands)


def test_ee_any_eku_accepted():
    root, ica, leaf = _simple_hierarchy(leaf_kw=dict(eku=[ANY_EKU]))
    _, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert len(valid) == 1


def test_ca_eku_then_ee_missing_eku_rejected():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, eku=[SERVER_AUTH])
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=None)
    cands, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert valid == []
    assert "ekuRequired" in reasons(cands)


def test_ca_eku_intersection_empty_rejected():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    k1, k2 = new_key(), new_key()
    ca1 = issue(subject_cn="CA1", subject_key=k1, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, eku=[CLIENT_AUTH])
    # CA1 只允许 clientAuth：它在自身这一层就该失败
    cands, valid = evaluate(root,
                            issue(subject_cn="x", subject_key=k2,
                                  issuer_cn="CA1", issuer_key=k1,
                                  is_ca=False, san_dns=("h.example.com",),
                                  eku=[SERVER_AUTH]),
                            [ca1], "h.example.com")
    assert valid == []
    assert "ekuServerAuth" in reasons(cands)


def test_two_cas_eku_intersection_keeps_server_auth():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True, path_len=2)
    k1, k2, sk = new_key(), new_key(), new_key()
    ca1 = issue(subject_cn="CA1", subject_key=k1, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=1,
                eku=[SERVER_AUTH, CLIENT_AUTH])
    ca2 = issue(subject_cn="CA2", subject_key=k2, issuer_cn="CA1",
                issuer_key=k1, is_ca=True, path_len=0, eku=[SERVER_AUTH])
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="CA2",
                 issuer_key=k2, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    _, valid = evaluate(root, leaf, [ca1, ca2], "h.example.com")
    assert len(valid) == 1


def test_ca_any_eku_then_ee_server_auth_accepted():
    # CA 给 ANY（通配），EE 收窄成 serverAuth：ANY 不能因朴素交集被清空
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, eku=[ANY_EKU])
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    _, valid = evaluate(root, leaf, [ica], "h.example.com")
    assert len(valid) == 1


def test_ca_server_auth_ee_any_accepted():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, eku=[SERVER_AUTH])
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[ANY_EKU])
    _, valid = evaluate(root, leaf, [ica], "h.example.com")
    assert len(valid) == 1


def test_ca_any_ee_client_auth_only_rejected():
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0, eku=[ANY_EKU])
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("h.example.com",),
                 eku=[CLIENT_AUTH])
    cands, valid = evaluate(root, leaf, [ica], "h.example.com")
    assert valid == []
    assert "ekuServerAuth" in reasons(cands)


# ---------------- pathLen ----------------

def _two_ca_chain(root_path_len=None, ca1_path_len=1):
    rk, k1, k2, sk = new_key(), new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 path_len=root_path_len)
    ca1 = issue(subject_cn="CA1", subject_key=k1, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=ca1_path_len)
    ca2 = issue(subject_cn="CA2", subject_key=k2, issuer_cn="CA1",
                issuer_key=k1, is_ca=True, path_len=0)
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="CA2",
                 issuer_key=k2, is_ca=False, san_dns=("h.example.com",),
                 eku=[SERVER_AUTH])
    return root, ca1, ca2, leaf


def test_pathlen_ok():
    root, ca1, ca2, leaf = _two_ca_chain(root_path_len=2, ca1_path_len=1)
    _, valid = evaluate(root, leaf, [ca1, ca2], "h.example.com")
    assert len(valid) == 1


def test_pathlen_root_zero_rejected():
    root, ca1, ca2, leaf = _two_ca_chain(root_path_len=0)
    cands, valid = evaluate(root, leaf, [ca1, ca2], "h.example.com")
    assert valid == []
    assert "pathLenExceeded" in reasons(cands)


def test_pathlen_ca1_zero_rejected():
    root, ca1, ca2, leaf = _two_ca_chain(root_path_len=2, ca1_path_len=0)
    cands, valid = evaluate(root, leaf, [ca1, ca2], "h.example.com")
    assert valid == []
    assert "pathLenExceeded" in reasons(cands)


def test_pathlen_none_unlimited():
    root, ca1, ca2, leaf = _two_ca_chain(root_path_len=None, ca1_path_len=None)
    # ca2 自带 path_len=0，其下只有 EE；OK
    _, valid = evaluate(root, leaf, [ca1, ca2], "h.example.com")
    assert len(valid) == 1


# ---------------- 锚豁免 ----------------

def test_anchor_expired_still_trusted():
    # 锚自身的有效期不计入本次链验证
    rk = new_key()
    root = issue(
        subject_cn="Root", subject_key=rk, is_ca=True,
        not_before=datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
    )
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0)
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    _, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert len(valid) == 1


def test_anchor_signature_not_verified():
    # 锚不是自签的（由一把无关密钥签出）也必须接受：锚签名不参与本次验证。
    rk, foreign = new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, issuer_cn="OtherRoot",
                 issuer_key=foreign, is_ca=True)
    ik = new_key()
    ica = issue(subject_cn="ICA", subject_key=ik, issuer_cn="Root",
                issuer_key=rk, is_ca=True, path_len=0)
    sk = new_key()
    leaf = issue(subject_cn="h", subject_key=sk, issuer_cn="ICA",
                 issuer_key=ik, is_ca=False, san_dns=("www.example.com",),
                 eku=[SERVER_AUTH])
    _, valid = evaluate(root, leaf, [ica], "www.example.com")
    assert len(valid) == 1


# ---------------- 档位拒绝 ----------------

def test_unknown_critical_extension_rejected(tmp_path=None):
    rk = new_key()
    crit_policy = x509.Extension(
        x509.oid.ExtensionOID.CERTIFICATE_POLICIES, True,
        x509.CertificatePolicies([x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3.4"), None)]),
    )
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 extra_extensions=(crit_policy,))
    with pytest.raises(ProfileError, match="未知的关键扩展"):
        check_static_profile(root, "anchor")


def test_unknown_non_critical_extension_allowed():
    rk = new_key()
    nc_policy = x509.Extension(
        x509.oid.ExtensionOID.CERTIFICATE_POLICIES, False,
        x509.CertificatePolicies([x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.3.4"), None)]),
    )
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True,
                 extra_extensions=(nc_policy,))
    check_static_profile(root, "anchor")  # 不抛异常


def test_san_with_email_rejected():
    rk, ik, sk = new_key(), new_key(), new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(cn("h"))
        .issuer_name(cn("Root"))
        .public_key(sk.public_key())
        .serial_number(1234)
        .not_valid_before(DEFAULT_NB).not_valid_after(DEFAULT_NA)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("www.example.com"),
             x509.RFC822Name("a@example.com")]), False)
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.ExtendedKeyUsage([SERVER_AUTH]), False)
        .sign(rk, __import__("cryptography.hazmat.primitives.hashes",
                             fromlist=["hashes"]).SHA256())
    )
    with pytest.raises(ProfileError, match="非 DNS 项"):
        check_static_profile(leaf, "ee")


def test_wildcard_san_rejected_at_profile():
    rk = new_key()
    leaf = issue(subject_cn="h", subject_key=new_key(), issuer_cn="Root",
                 issuer_key=rk, is_ca=False, san_dns=("*.example.com",),
                 eku=[SERVER_AUTH])
    with pytest.raises(ProfileError, match="通配符"):
        check_static_profile(leaf, "ee")


def test_non_ascii_target_rejected_at_cli(tmp_path):
    root, ica, leaf = _simple_hierarchy()
    rc, payload, err = run_cli(tmp_path, root, leaf, [ica],
                               "www.exämple.com", AT_TIME)
    assert rc == 2
    assert "ASCII" in err


def test_rsa_leaf_rejected(tmp_path):
    rk = new_key()
    root = issue(subject_cn="Root", subject_key=rk, is_ca=True)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(cn("h"))
        .issuer_name(cn("Root"))
        .public_key(rsa_key.public_key())
        .serial_number(4321)
        .not_valid_before(DEFAULT_NB).not_valid_after(DEFAULT_NA)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("www.example.com")]), False)
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.ExtendedKeyUsage([SERVER_AUTH]), False)
        .sign(rk, __import__("cryptography.hazmat.primitives.hashes",
                             fromlist=["hashes"]).SHA256())
    )
    with pytest.raises(ProfileError):
        check_static_profile(leaf, "ee")
