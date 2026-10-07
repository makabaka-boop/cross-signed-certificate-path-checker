"""候选链建立：从服务器证书向上枚举到固定信任锚。

只接受“实际签名成立”的发行关系（调用 certutil.verify_one_signature
做单张验签），不调用任何完整路径验证器。同名 CA 不同密钥、交叉签发
的情况在这里自然展开为多条候选链：发行者同名但签名验不过的证书
不会成为发行者，而另一条链上真正签它的同名证书会被枚举到。

防环：DFS 路径上按证书 DER 摘要去重；
self-issued 换钥节点（subject==issuer 但由另一把同名密钥签发）
验签用的是发行者公钥，因此不会被当成自签可信根；
只有固定下来的锚对象可以终止一条链。
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509

from .certutil import (
    cert_sha256,
    get_aki,
    get_ski,
    is_self_issued,
    same_name,
    verify_one_signature,
)
from .dnsnames import normalize_dns
from .validate import Failure, validate_path

# 链中允许的中间证书数量上限（输入侧至多 8 张无序中间证书）
MAX_INTERMEDIATES = 8


@dataclass(frozen=True)
class Candidate:
    """一条枚举到的候选链。

    chain: 锚 → EE 方向的证书序列；未接到锚的断头路径没有锚，
           序列按“最靠近锚的尝试节点 → EE”给出（顶部即为断头证书）。
    reaches_anchor: 该候选是否真正接到固定信任锚。
    failure: 语义验证的首个失败；None 仅在接到锚且全链合法时出现。
    """

    chain: tuple[x509.Certificate, ...]
    reaches_anchor: bool
    failure: Failure | None

    @property
    def valid(self) -> bool:
        return self.reaches_anchor and self.failure is None

    def digest_tuple(self) -> tuple[str, ...]:
        return tuple(cert_sha256(c) for c in self.chain)


def _aki_skid_compatible(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    aki = get_aki(child)
    skid = get_ski(issuer)
    if aki is not None and skid is not None and aki != skid:
        return False
    return True


def _eligible_issuers(
    child: x509.Certificate,
    intermediates: list[x509.Certificate],
    used_digests: frozenset[str],
) -> list[x509.Certificate]:
    """找出一张证书的全部“同名 + AKI 匹配 + 验签成立”的中间证书发行者。"""
    out: list[x509.Certificate] = []
    for cand in intermediates:
        if cert_sha256(cand) in used_digests:
            continue  # 防环
        if not same_name(cand.subject, child.issuer):
            continue
        if not _aki_skid_compatible(child, cand):
            continue
        if not verify_one_signature(child, cand):
            continue
        # 自签边（self-issued 且由自己的公钥签成）不可能通向其它发行者，
        # 更不能充当信任根；跳过它，避免环产生重复候选。
        # 注意：self-issued 换钥节点验签者公钥 != 证书自身公钥，
        # verify_one_signature(cand, cand) 为 False，不会被误跳过——
        # 它必须继续向上找到真正签它的 CA。
        if is_self_issued(cand) and verify_one_signature(cand, cand):
            continue
        out.append(cand)
    out.sort(key=cert_sha256)
    return out


def build_candidates(
    anchor: x509.Certificate,
    ee: x509.Certificate,
    intermediates: list[x509.Certificate],
    target_dns: str,
    at_time,
) -> list[Candidate]:
    """枚举全部极大简单路径并对接到锚的链做受限 RFC 5280 验证。

    返回的候选按 DER 摘要序列排序，保证：
      * 输入中间证书的排列顺序不影响枚举内容与最终信任结论；
      * 多条合法链时，展示路径由摘要序列唯一确定。
    """
    target_dns = normalize_dns(target_dns)
    # 输入去重（同 DER 视为同一张证书）
    unique: dict[str, x509.Certificate] = {}
    for c in intermediates:
        unique.setdefault(cert_sha256(c), c)
    # 信任锚只能终止一条链，不能在路径中间出现；即使调用方把同一 DER
    # 证书也放进了中间证书池，也把它从向上枚举的候选中剔除。
    unique.pop(cert_sha256(anchor), None)
    inters = sorted(unique.values(), key=cert_sha256)

    results: dict[tuple[str, ...], Candidate] = {}
    ee_digest = cert_sha256(ee)

    def record(chain_anchor_to_ee: list[x509.Certificate],
               reaches_anchor: bool, failure: Failure | None) -> None:
        key = tuple(cert_sha256(c) for c in chain_anchor_to_ee)
        if key in results:
            return
        results[key] = Candidate(tuple(chain_anchor_to_ee), reaches_anchor, failure)

    def dead_end_failure(path_up: list[x509.Certificate], reason: str,
                         detail: str) -> Failure:
        # path_up: [EE, parent, ...]，断头证书是最后一个
        top = path_up[-1]
        return Failure(
            depth=-1,
            sha256=cert_sha256(top),
            subject=top.subject.rfc4514_string(),
            reason=reason,
            detail=detail,
        )

    def dfs(path_up: list[x509.Certificate], used: frozenset[str]) -> None:
        current = path_up[-1]

        # 1) 固定锚能否终止本路径：同名 + AKI 匹配 + 锚的公钥真的签了它
        anchor_linked = False
        if same_name(anchor.subject, current.issuer) and \
                _aki_skid_compatible(current, anchor):
            if verify_one_signature(current, anchor):
                chain = [anchor] + list(reversed(path_up))
                failure = validate_path(chain, target_dns, at_time)
                record(chain, True, failure)
                anchor_linked = True
        # 注意：锚之上不再继续枚举。

        # 2) 当前路径上已有多少张中间证书（EE 之外、锚之前）
        intermediate_count_so_far = len(path_up) - 1

        # 3) 向中间证书继续扩展
        issuers = _eligible_issuers(current, inters, used)

        # 输入最多 8 张去重中间证书；若路径已用尽名额（此时所有中间证书
        # 都在 used 中，issuers 必为空），会在下面按断头路径记录。
        if issuers:
            for issuer in issuers:
                dfs(path_up + [issuer], used | {cert_sha256(issuer)})
            return

        # 4) 没有可继续的中间发行者：极大路径
        if anchor_linked:
            return
        # 区分几种断头原因，便于报告“首先失败的证书”
        if intermediate_count_so_far >= MAX_INTERMEDIATES:
            reason, detail = "depthLimit", (
                f"中间证书数已达上限 {MAX_INTERMEDIATES}，仍未接到信任锚")
        elif is_self_issued(current):
            reason, detail = "untrustedSelfIssued", (
                "路径终止于 self-issued 证书；它未被固定锚签发，"
                "self-issued 换钥节点不能当作自签可信根")
        else:
            reason, detail = "issuerNotFound", (
                f"在提供的中间证书与信任锚中，找不到发行者 "
                f"{current.issuer.rfc4514_string()} 且验签成立的证书")
        chain_partial = list(reversed(path_up))
        record(chain_partial, False, dead_end_failure(path_up, reason, detail))

    dfs([ee], frozenset({ee_digest}))

    return sorted(results.values(), key=lambda cand: cand.digest_tuple())
