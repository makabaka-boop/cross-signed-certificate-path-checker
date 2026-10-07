"""测试用 P-256 证书工厂：用 cryptography 的签发原语构造各种拓扑。

这里使用 cryptography 仅负责“签发/编码”，
被测工具 x509verify 自身不调用其完整路径验证器。
"""

from __future__ import annotations

import datetime
import random
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEFAULT_NB = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
DEFAULT_NA = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
AT_TIME = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)

SERVER_AUTH = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
CLIENT_AUTH = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
ANY_EKU = x509.ObjectIdentifier("2.5.29.37.0")


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def cn(name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


def _ski_ext(key: ec.EllipticCurvePublicKey) -> x509.Extension:
    return x509.Extension(
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        False,
        x509.SubjectKeyIdentifier.from_public_key(key),
    )


def name_constraints(permitted=(), excluded=(), critical=True) -> x509.Extension:
    return x509.Extension(
        x509.oid.ExtensionOID.NAME_CONSTRAINTS,
        critical,
        x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(d) for d in permitted] or None,
            excluded_subtrees=[x509.DNSName(d) for d in excluded] or None,
        ),
    )


@dataclass
class Issued:
    cert: x509.Certificate
    key: object


def issue(
    *,
    subject_cn: str,
    subject_key,
    issuer_cn: str | None = None,
    issuer_key=None,
    is_ca: bool,
    path_len: int | None = None,
    san_dns: tuple[str, ...] = (),
    nc: x509.Extension | None = None,
    eku: list | None = None,
    critical_eku: bool = False,
    not_before: datetime.datetime = DEFAULT_NB,
    not_after: datetime.datetime = DEFAULT_NA,
    extra_extensions: tuple[x509.Extension, ...] = (),
    include_ku: bool = True,
    include_bc: bool = True,
    include_aki: bool = True,
    signature_hash=hashes.SHA256(),
    serial: int | None = None,
) -> x509.Certificate:
    """签发一张证书。issuer_key 为 None 时自签（subject==issuer）。"""
    if issuer_key is None:
        issuer_key = subject_key
        issuer_cn = subject_cn

    builder = (
        x509.CertificateBuilder()
        .subject_name(cn(subject_cn))
        .issuer_name(cn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial if serial is not None else random.randint(1, 2**63))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            False,
        )
    )
    if include_aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            False,
        )

    if include_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_len), True
        )

    if include_ku:
        if is_ca:
            ku = x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            )
        else:
            ku = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        builder = builder.add_extension(ku, True)

    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            False,
        )

    if nc is not None:
        builder = builder.add_extension(nc.value, nc.critical)

    if eku is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku), critical_eku
        )

    for ext in extra_extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    return builder.sign(issuer_key, signature_hash)


def skid_of(key) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)