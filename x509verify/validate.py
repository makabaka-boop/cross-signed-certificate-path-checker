"""候选链的 RFC 5280 受限语义验证。

输入的 chain 已经是“签名实际成立”的候选链：
    [anchor, CA1, CA2, ..., EE]
建链（枚举无序中间证书、防环、单张验签）在 chain.py；
本模块只对一条已成立的候选链做顺序裁决，并报告“首先失败的那张证书”。

检查顺序（RFC 5280 §6 与本工具的受限子集）：
  对深度 d 从 1 到 n：
    1. 有效期（锚豁免）
    2. 名称约束：先并入第 d-1 张（发行者）的 NC，再用累计约束检查当前证书
       SAN 中全部 DNS 项；EE 额外要求精确目标名在 SAN 中
    3. BasicConstraints / KeyUsage（CA 位、keyCertSign 等）
    4. ExtendedKeyUsage 的逐层传播（含 serverAuth、anyExtendedKeyUsage）
  全部走完后：
    5. 逐层 pathLenConstraint 与累计中间 CA 计数（self-issued 换钥节点不计数）
锚自身的签名、有效期、BasicConstraints/KeyUsage 均不计入本次链验证。
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509

from .certutil import (
    cert_sha256,
    get_basic_constraints,
    get_eku,
    get_key_usage,
    get_name_constraints,
    get_san,
)
from .dnsnames import any_excluded, permitted_groups_accept
from .profiles import ANY_EKU_OID


@dataclass(frozen=True)
class Failure:
    """某条候选链上首先失败的证书与约束。"""

    depth: int
    sha256: str
    subject: str
    reason: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "depth": self.depth,
            "sha256": self.sha256,
            "subject": self.subject,
            "reason": self.reason,
            "detail": self.detail,
        }


def _subject_str(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return "<unprintable-subject>"


def _dns_names_of_san(cert: x509.Certificate) -> list[str]:
    san = get_san(cert)
    return [] if san is None else list(san.get_values_for_type(x509.DNSName))


def _nc_dns_lists(nc) -> tuple[list[str], list[str]]:
    def names(subtree) -> list[str]:
        if subtree is None:
            return []
        return [g.value for g in subtree if isinstance(g, x509.DNSName)]

    return names(nc.permitted_subtrees), names(nc.excluded_subtrees)


def _merge_nc(
    permitted_groups: list[list[str]],
    excluded: list[str],
    cert: x509.Certificate,
) -> tuple[list[list[str]], list[str]]:
    nc = get_name_constraints(cert)
    if nc is None:
        return permitted_groups, excluded
    permitted, exc = _nc_dns_lists(nc)
    # 只要该证书带有 permittedSubtrees 段（哪怕为空列表），就作为新的
    # 一组交集约束并入；空组表示“任何 DNS 名都不许”。
    if nc.permitted_subtrees is not None:
        permitted_groups = permitted_groups + [permitted]
    return permitted_groups, excluded + exc


def _check_nc_against_names(
    cert: x509.Certificate,
    depth: int,
    dns_names: list[str],
    permitted_groups: list[list[str]],
    excluded: list[str],
) -> Failure | None:
    for name in dns_names:
        if any_excluded(name, excluded):
            return Failure(
                depth,
                cert_sha256(cert),
                _subject_str(cert),
                "nameConstraints_excluded",
                f"DNS 名 {name!r} 命中累计排除子树",
            )
        if not permitted_groups_accept(name, permitted_groups):
            covering = []
            for group in permitted_groups:
                covering.append(
                    "[" + ", ".join(repr(c) for c in group) + "]"
                )
            return Failure(
                depth,
                cert_sha256(cert),
                _subject_str(cert),
                "nameConstraints_permitted",
                f"DNS 名 {name!r} 不被累计允许子树交集覆盖: "
                + " 且 ".join(covering),
            )
    return None


def _check_ca_basic_ku(cert: x509.Certificate, depth: int) -> Failure | None:
    bc = get_basic_constraints(cert)
    if bc is None or not bc.ca:
        return Failure(
            depth,
            cert_sha256(cert),
            _subject_str(cert),
            "notCA",
            "中间证书缺少 cA=TRUE 的 BasicConstraints",
        )

    ku = get_key_usage(cert)
    if ku is None:
        # RFC 5280: 验证 CA 证书必须包含含 keyCertSign 的 critical KeyUsage。
        return Failure(
            depth,
            cert_sha256(cert),
            _subject_str(cert),
            "missingKeyUsage",
            "CA 证书必须含 KeyUsage 且包含 keyCertSign",
        )
    if not ku.key_cert_sign:
        return Failure(
            depth,
            cert_sha256(cert),
            _subject_str(cert),
            "keyUsage",
            "CA 证书的 KeyUsage 不含 keyCertSign",
        )
    return None


def _check_ee_basic_ku(cert: x509.Certificate, depth: int) -> Failure | None:
    bc = get_basic_constraints(cert)
    if bc is not None and bc.ca:
        return Failure(
            depth,
            cert_sha256(cert),
            _subject_str(cert),
            "eeIsCA",
            "末端服务器证书带 cA=TRUE",
        )
    ku = get_key_usage(cert)
    if ku is not None:
        if ku.key_cert_sign:
            return Failure(
                depth,
                cert_sha256(cert),
                _subject_str(cert),
                "eeKeyCertSign",
                "末端服务器证书的 KeyUsage 含 keyCertSign",
            )
        # RFC 5280 4.2.1.3: EE 证书若含 KeyUsage，用于服务器认证时
        # digitalSignature 位必须置位（ECDSA 签名场景）。
        if not ku.digital_signature:
            return Failure(
                depth,
                cert_sha256(cert),
                _subject_str(cert),
                "eeKeyUsage",
                "末端服务器证书的 KeyUsage 不含 digitalSignature",
            )
    return None


def _eku_set(cert: x509.Certificate) -> frozenset[x509.ObjectIdentifier] | None:
    eku = get_eku(cert)
    if eku is None:
        return None
    return frozenset(eku)


def _eku_combine(required: frozenset, this: frozenset) -> frozenset:
    """两层 EKU 的“交集”，正确处理 anyExtendedKeyUsage 通配符。

    * 两层都含 ANY          -> 仍是 ANY；
    * required 含 ANY      -> this 施加什么就是什么；
    * this 含 ANY          -> this 不额外收窄，沿用 required；
    * 否则                 -> 普通集合交集。
    """
    if ANY_EKU_OID in required and ANY_EKU_OID in this:
        return frozenset({ANY_EKU_OID})
    if ANY_EKU_OID in required:
        return this
    if ANY_EKU_OID in this:
        return required
    return required & this


def _purpose_present(required: frozenset | None,
                     this: frozenset,
                     purpose=x509.oid.ExtendedKeyUsageOID.SERVER_AUTH) -> bool:
    combined = this if required is None else _eku_combine(required, this)
    return purpose in combined or ANY_EKU_OID in combined


def validate_path(
    chain: list[x509.Certificate],
    target_dns: str,
    at_time,
) -> Failure | None:
    """对一条签名已成立的候选链做受限 RFC 5280 验证。

    返回 None 表示该链合法；否则返回链上首先失败证书的 Failure。
    """
    # 名称约束累计状态（由每个发行者施加给其下级）
    permitted_groups: list[list[str]] = []
    excluded: list[str] = []

    # EKU 传播状态机（RFC 5280 4.2.1.12）：
    #   None        —— 尚未出现任何 EKU 扩展（此时尚未“需要”EKU）
    #   frozenset   —— 上一张带 EKU 的 CA 所要求的用途交集
    #   frozenset() —— 空集：传播链已经断裂（上层要求、下层缺失或用途被清空）
    required_ekus: frozenset | None = None

    n = len(chain) - 1  # EE 的深度
    if n < 1:
        return Failure(0, cert_sha256(chain[0]), _subject_str(chain[0]),
                       "emptyPath", "链只有锚，没有服务器证书")

    for depth in range(1, n + 1):
        cert = chain[depth]
        sha = cert_sha256(cert)
        subject = _subject_str(cert)
        is_ee = depth == n

        # ---- 1. 有效期（锚豁免）----------------------------------------
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:  # 极旧版 cryptography 回退
            from datetime import timezone

            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if at_time < not_before:
            return Failure(depth, sha, subject, "notYetValid",
                           f"notBefore={not_before.isoformat()}，"
                           f"验证时刻 {at_time.isoformat()} 早于生效时间")
        if at_time > not_after:
            return Failure(depth, sha, subject, "expired",
                           f"notAfter={not_after.isoformat()}，"
                           f"验证时刻 {at_time.isoformat()} 已过期")

        # ---- 2. 发行者名称约束并入，再检查当前证书 ----------------------
        issuer = chain[depth - 1]
        permitted_groups, excluded = _merge_nc(permitted_groups, excluded, issuer)

        dns_names = _dns_names_of_san(cert)
        if is_ee:
            if not dns_names:
                return Failure(depth, sha, subject, "missingSAN",
                               "服务器证书没有 dNSName 形式的 SAN")
            # 精确匹配：小写、去尾点后等值比较；本工具不做通配符。
            if not any(n.lower().rstrip(".") == target_dns for n in dns_names):
                return Failure(depth, sha, subject, "nameMismatch",
                               f"SAN {sorted(n.lower() for n in dns_names)} "
                               f"不含精确目标名 {target_dns!r}")
        nc_failure = _check_nc_against_names(
            cert, depth, dns_names, permitted_groups, excluded
        )
        if nc_failure is not None:
            return nc_failure

        # ---- 3. BasicConstraints / KeyUsage -----------------------------
        if is_ee:
            basic_failure = _check_ee_basic_ku(cert, depth)
        else:
            basic_failure = _check_ca_basic_ku(cert, depth)
        if basic_failure is not None:
            return basic_failure

        # ---- 4. EKU 逐层传播（含 anyExtendedKeyUsage 通配语义）---------
        this_eku = _eku_set(cert)
        if is_ee:
            if required_ekus is not None and this_eku is None:
                # 此前 CA 要求了 EKU：EE 必须带 EKU
                return Failure(depth, sha, subject, "ekuRequired",
                               "上层 CA 含 EKU，末端证书缺失 EKU 扩展")
            if this_eku is None:
                # 上层从未要求 EKU：EE 自身仍必须声明 serverAuth（或 ANY），
                # 缺失 EKU 不能用于服务器认证。
                return Failure(depth, sha, subject, "ekuRequired",
                               "服务器证书缺少 EKU，无法断言 serverAuth 用途")
            if not _purpose_present(required_ekus, this_eku):
                return Failure(depth, sha, subject, "ekuServerAuth",
                               "沿链传播后的 EKU 有效用途不含 serverAuth")
        else:
            if this_eku is not None:
                # 先确认本层（与上层的交集）仍允许 serverAuth 继续向下传
                if not _purpose_present(required_ekus, this_eku):
                    return Failure(depth, sha, subject, "ekuServerAuth",
                                   "CA 的 EKU 与上层交集不含 serverAuth，"
                                   "不能继续签发服务器认证链")
                required_ekus = (
                    this_eku if required_ekus is None
                    else _eku_combine(required_ekus, this_eku)
                )
            elif required_ekus is not None:
                # RFC 5280: 若链上任一 CA 证书包含 EKU，则其后所有证书
                # 都必须包含 EKU。
                return Failure(depth, sha, subject, "ekuRequired",
                               "上层 CA 含 EKU，本层 CA 缺失 EKU 扩展")

    # ---- 5. pathLenConstraint 与累计中间 CA 计数 -------------------------
    # RFC 5280: pathLenConstraint 限制该 CA 之下允许出现的非自签
    # （这里按 self-issued 口径豁免换钥节点）中间 CA 的数量。
    # 对链上每个带 pathLen 的 CA，单独数它“下方到当前节点之间”的
    # 非 self-issued CA 数，超过即失败（失败记在当前进入的证书上）。
    for depth in range(1, n + 1):
        cert = chain[depth]
        for upper_depth in range(0, depth):
            upper = chain[upper_depth]
            upper_bc = get_basic_constraints(upper)
            if upper_bc is None or not upper_bc.ca:
                continue
            if upper_bc.path_length is None:
                continue
            between = 0
            for mid in range(upper_depth + 1, depth):
                mid_cert = chain[mid]
                mid_self_issued = (
                    mid_cert.subject.public_bytes()
                    == mid_cert.issuer.public_bytes()
                )
                if not mid_self_issued:
                    between += 1
            if between > upper_bc.path_length:
                return Failure(
                    depth,
                    cert_sha256(cert),
                    _subject_str(cert),
                    "pathLenExceeded",
                    f"深度 {upper_depth} 处 CA 的 pathLenConstraint="
                    f"{upper_bc.path_length}，其下方到本证书之间已有 "
                    f"{between} 个非 self-issued 中间 CA",
                )

    return None
