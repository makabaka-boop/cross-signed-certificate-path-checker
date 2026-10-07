"""静态档位检查：证书是否落在本工具接受的受限输入域内。

这些检查与“某条链能否成立”无关，只针对单张证书本身：
* 签名算法必须是 ecdsa-with-SHA256；
* 主体公钥必须是 P-256（secp256r1）上的 EC 公钥；
* 出现的关键扩展必须是本工具实现的扩展，未知 critical 一律拒绝；
* subjectAltName 若存在，只能含 dNSName 项，且为非空 ASCII、无通配符；
* nameConstraints 若存在，permitted/excluded 子树只能含 dNSName 项。

锚证书同样过档位检查（我们固定的就是一个 P-256 锚）；
锚“自身签名是否成立、是否在有效期内”不属于本次链验证，在 validate 中豁免。
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from .certutil import get_extension
from .errors import ProfileError

# 本工具“实现了语义”的扩展。其中 critical 与否按 RFC 要求在 validate 里处理；
# 除此之外的任何扩展只要标记 critical 即拒绝（RFC 5280 4.2）。
KNOWN_EXTENSION_OIDS: frozenset[x509.ObjectIdentifier] = frozenset(
    {
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
        x509.oid.ExtensionOID.KEY_USAGE,
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        x509.oid.ExtensionOID.NAME_CONSTRAINTS,
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    }
)

SERVER_AUTH_OID = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
ANY_EKU_OID = x509.ObjectIdentifier("2.5.29.37.0")


def _check_algorithm_and_key(cert: x509.Certificate, where: str) -> None:
    if cert.signature_algorithm_oid != x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
        raise ProfileError(
            f"{where}: 仅接受 ecdsa-with-SHA256 签名算法，实际为 "
            f"{cert.signature_algorithm_oid.dotted_string}"
        )
    pk = cert.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey) or not isinstance(
        pk.curve, ec.SECP256R1
    ):
        kind = type(pk).__name__
        curve = getattr(pk, "curve", None)
        raise ProfileError(
            f"{where}: 仅接受 P-256(secp256r1) EC 公钥，实际为 {kind}"
            + (f"/{type(curve).__name__}" if curve is not None else "")
        )


def _check_san_shape(cert: x509.Certificate, where: str) -> None:
    san_ext = get_extension(cert, x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san_ext is None:
        return
    san = san_ext.value
    seen = 0
    for general_name in san:
        if not isinstance(general_name, x509.DNSName):
            raise ProfileError(
                f"{where}: subjectAltName 含非 DNS 项 ({type(general_name).__name__})，"
                "本工具仅接受 DNS 项"
            )
        value = general_name.value
        seen += 1
        if not value:
            raise ProfileError(f"{where}: subjectAltName 含空 DNS 项")
        if not value.isascii():
            raise ProfileError(f"{where}: subjectAltName 含非 ASCII DNS 项 {value!r}")
        if "*" in value:
            raise ProfileError(f"{where}: 本工具不支持通配符 DNS 项 {value!r}")
    if seen == 0:
        raise ProfileError(f"{where}: subjectAltName 扩展为空")


def _check_nc_shape(cert: x509.Certificate, where: str) -> None:
    nc_ext = get_extension(cert, x509.oid.ExtensionOID.NAME_CONSTRAINTS)
    if nc_ext is None:
        return
    nc = nc_ext.value
    for subtree_kind, subtree in (
        ("permitted", nc.permitted_subtrees),
        ("excluded", nc.excluded_subtrees),
    ):
        if subtree is None:
            continue
        for general_name in subtree:
            if not isinstance(general_name, x509.DNSName):
                raise ProfileError(
                    f"{where}: nameConstraints 的 {subtree_kind} 子树含非 DNS 项 "
                    f"({type(general_name).__name__})，本工具仅接受 DNS 项"
                )
            value = general_name.value
            # NC 中允许 ""（表示全部）与 ".example.com"/"example.com"
            if value and not value.isascii():
                raise ProfileError(
                    f"{where}: nameConstraints 的 {subtree_kind} 子树含非 ASCII "
                    f"DNS 项 {value!r}"
                )
            if "*" in value:
                raise ProfileError(
                    f"{where}: nameConstraints 不接受通配符 {value!r}"
                )


def check_static_profile(cert: x509.Certificate, where: str) -> None:
    """对单张证书执行全部静态档位检查，不合格即抛 ProfileError。"""
    _check_algorithm_and_key(cert, where)

    for ext in cert.extensions:
        if ext.critical and ext.oid not in KNOWN_EXTENSION_OIDS:
            name = getattr(ext.value, "__class__", type(ext.value)).__name__
            raise ProfileError(
                f"{where}: 存在未知的关键扩展 OID {ext.oid.dotted_string} ({name})，"
                "按 RFC 5280 必须拒绝"
            )

    _check_san_shape(cert, where)
    _check_nc_shape(cert, where)
