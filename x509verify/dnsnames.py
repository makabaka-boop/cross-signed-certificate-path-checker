"""DNS 名称的规范化与 RFC 5280 名称约束匹配。

本工具刻意只支持 ASCII：
* 精确目标名：不做 IDNA、不做通配符，按小写后逐字符比较；
* 名称约束 / SAN 中的 dNSName：
  - 普通名（如 ``host.example.com``）：仅匹配完全同名；
  - 前导点名（如 ``.example.com``）：匹配该域及其任意子域。

空字符串 ``""`` 按 RFC 5280 4.2.1.10 的实现惯例视为“匹配所有 DNS 名”
（作为 permitted 时）；排除侧出现空串则表示排除一切。
"""

from __future__ import annotations


def normalize_dns(name: str) -> str:
    """小写化并去掉结尾根点；不接受非 ASCII。"""
    if not name.isascii():
        raise ValueError("仅支持 ASCII DNS 名")
    out = name.lower()
    if out.endswith("."):
        out = out[:-1]
    return out


def assert_ascii_dns(name: str) -> str:
    """命令行目标名入口：必须是 ASCII、非空、不含通配符。"""
    if not name:
        raise ValueError("DNS 名为空")
    if not name.isascii():
        raise ValueError(f"DNS 名不是 ASCII: {name!r}")
    if "*" in name:
        raise ValueError(f"本工具不支持通配符: {name!r}")
    return normalize_dns(name)


def _label_wellformed(name: str) -> bool:
    """目标名的最小标签合法性检查：标签非空、字母数字连字符、不以连字符开头结尾。"""
    if not name:
        return False
    for label in name.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in label):
            return False
    return True


def assert_target_dns(name: str) -> str:
    n = assert_ascii_dns(name)
    if not _label_wellformed(n):
        raise ValueError(f"DNS 名标签不合法: {name!r}")
    return n


def dns_constraint_matches(constraint: str, target: str) -> bool:
    """单个 dNSName 约束是否覆盖目标名（两侧均按小写处理）。"""
    c = normalize_dns(constraint)
    t = normalize_dns(target)
    if c == "":
        return True
    if c.startswith("."):
        suffix = c[1:]
        # ".example.com" 匹配 example.com 与其子域；
        # 形如 "." 的退化形式匹配一切非空名。
        if suffix == "":
            return bool(t)
        return t == suffix or t.endswith("." + suffix)
    return t == c


def any_excluded(target: str, excluded: list[str]) -> bool:
    return any(dns_constraint_matches(c, target) for c in excluded)


def permitted_groups_accept(target: str, permitted_groups: list[list[str]]) -> bool:
    """累计的 permitted 取交集：每一组都必须有一项覆盖目标。

    permitted_groups 为空表示上层从未施加 permitted，即全部放行。
    """
    for group in permitted_groups:
        if not any(dns_constraint_matches(c, target) for c in group):
            return False
    return True
