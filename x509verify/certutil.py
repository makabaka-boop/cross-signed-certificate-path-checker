"""证书加载、DER 摘要与各扩展的低层读取。

本模块只负责“取数”，不做任何 RFC 5280 裁决；
签名也只提供单张验签原语，绝不调用 cryptography 的完整路径验证器。
"""

from __future__ import annotations

import hashlib
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .errors import InputError

_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def load_cert_file(path: str) -> list[x509.Certificate]:
    """加载一个证书文件。

    支持单个 DER、单个 PEM，以及一个文件内串联的多张 PEM。
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise InputError(f"无法读取证书文件 {path}: {exc}") from exc

    data_stripped = data.lstrip()
    certs: list[x509.Certificate] = []

    if data_stripped.startswith(b"-----BEGIN"):
        for block in _PEM_BLOCK_RE.findall(data):
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except Exception as exc:  # cryptography 的异常类型较分散
                raise InputError(f"文件 {path} 中有无法解析的 PEM 证书: {exc}") from exc
        if not certs:
            raise InputError(f"文件 {path} 看起来是 PEM，但没有找到合法 CERTIFICATE 块")
        return certs

    # 退化为 DER
    try:
        certs.append(x509.load_der_x509_certificate(data))
    except Exception as exc:
        raise InputError(f"文件 {path} 既不是合法 PEM 也不是合法 DER 证书: {exc}") from exc
    return certs


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cert_sha256(cert: x509.Certificate) -> str:
    """证书 DER 的 SHA-256，小写十六进制；这是本工具的证书唯一标识。"""
    return hashlib.sha256(cert_der(cert)).hexdigest()


def cert_sha256_bytes(cert: x509.Certificate) -> bytes:
    return hashlib.sha256(cert_der(cert)).digest()


def same_name(a: x509.Name, b: x509.Name) -> bool:
    """按 DER 编码比较两个 Name（规范化后逐字节比，等价于 RDN 序列比较）。"""
    return a.public_bytes() == b.public_bytes()


def is_self_issued(cert: x509.Certificate) -> bool:
    """RFC 5280 4.2.1.9: subject 与 issuer 同名即为 self-issued（不等于 self-signed）。"""
    return same_name(cert.subject, cert.issuer)


def verify_one_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """只验一张证书对一张发行者的签名，不触及其它任何路径语义。

    仅接受 ECDSA-with-SHA256 / P-256，其余一律返回 False；
    内部做严格 DER-SigValue 与曲线阶长度检查，不接受畸形签名。
    """
    try:
        issuer_pk = issuer.public_key()
        if not isinstance(issuer_pk, ec.EllipticCurvePublicKey):
            return False
        if not isinstance(issuer_pk.curve, ec.SECP256R1):
            return False
        if cert.signature_algorithm_oid != x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
            return False

        # 严格检查 SigValue：DER(SEQUENCE { r INTEGER, s INTEGER })，
        # r、s 均为正数且不超过曲线阶位宽。
        sig = cert.signature
        order = issuer_pk.curve.key_size
        r, s = decode_dss_signature(sig)
        if r <= 0 or s <= 0:
            return False
        if r.bit_length() > order or s.bit_length() > order:
            return False

        issuer_pk.verify(
            sig,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 扩展读取：全部返回 None 表示“不存在该扩展”。
# ---------------------------------------------------------------------------

def get_extension(cert: x509.Certificate, oid: x509.ObjectIdentifier):
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def get_san(cert: x509.Certificate):
    ext = get_extension(cert, x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    return None if ext is None else ext.value


def get_name_constraints(cert: x509.Certificate):
    ext = get_extension(cert, x509.oid.ExtensionOID.NAME_CONSTRAINTS)
    return None if ext is None else ext.value


def get_basic_constraints(cert: x509.Certificate):
    ext = get_extension(cert, x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    return None if ext is None else ext.value


def get_key_usage(cert: x509.Certificate):
    ext = get_extension(cert, x509.oid.ExtensionOID.KEY_USAGE)
    return None if ext is None else ext.value


def get_eku(cert: x509.Certificate):
    ext = get_extension(cert, x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
    return None if ext is None else ext.value


def get_ski(cert: x509.Certificate) -> bytes | None:
    ext = get_extension(cert, x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return None if ext is None else ext.value.digest


def get_aki(cert: x509.Certificate) -> bytes | None:
    ext = get_extension(cert, x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if ext is None or ext.value.key_identifier is None:
        return None
    return ext.value.key_identifier
