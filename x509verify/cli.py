"""受限 X.509 路径验证的命令行入口（离线，无任何网络查询）。

用法示例：
    python -m x509verify.cli \
        --anchor root.pem --pin 9f86d081... \
        --server leaf.pem \
        --intermediate intca-1.pem --intermediate cross.pem \
        --at-time 2026-06-01T00:00:00Z \
        --name www.example.com

退出码：0 存在合法链；1 无合法链；2 输入/用法错误；3 内部错误。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .chain import MAX_INTERMEDIATES, build_candidates
from .certutil import cert_sha256, load_cert_file
from .errors import InputError, ProfileError, X509VerifyError
from .profiles import check_static_profile


def _parse_at_time(text: str) -> datetime:
    raw = text.strip()
    candidates = (raw,)
    if raw.endswith("Z"):
        candidates = (raw[:-1] + "+00:00", raw[:-1])
    for value in candidates:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise InputError(f"无法解析验证时刻 {text!r}，请使用 ISO-8601（如 2026-06-01T00:00:00Z）")


def _cert_node(cert, depth: int) -> dict:
    return {
        "depth": depth,
        "sha256": cert_sha256(cert),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="x509verify",
        description=(
            "受限 X.509 路径验证（仅 P-256 / ECDSA-SHA256、纯 DNS SAN、"
            "精确 ASCII 名；离线，不做撤销/策略/通配符；不使用完整路径验证器）"
        ),
    )
    p.add_argument("--anchor", required=True, help="信任锚证书文件（PEM 或 DER，单张）")
    p.add_argument("--pin", required=True,
                   help="锚证书 DER 的 SHA-256（十六进制，大小写/空白不敏感）")
    p.add_argument("--server", required=True, help="待验服务器证书文件（PEM 或 DER）")
    p.add_argument("--intermediate", "--untrusted", action="append", default=[],
                   help="中间证书文件；可重复，每个文件可含一张或多张 PEM，"
                        f"合计至多 {MAX_INTERMEDIATES} 张")
    p.add_argument("--at-time", required=True, help="验证时刻（ISO-8601，UTC）")
    p.add_argument("--name", required=True, help="要验证的精确 DNS 名（ASCII，不支持通配符）")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="以 JSON 输出（默认人类可读文本）")
    return p


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        at_time = _parse_at_time(args.at_time)

        # DNS 目标名先过 ASCII / 标签合法性
        from .dnsnames import assert_target_dns
        try:
            target_dns = assert_target_dns(args.name)
        except ValueError as exc:
            raise InputError(str(exc)) from exc

        anchors = load_cert_file(args.anchor)
        if len(anchors) != 1:
            raise InputError(f"信任锚文件必须恰好包含 1 张证书，实际 {len(anchors)} 张")
        anchor = anchors[0]

        servers = load_cert_file(args.server)
        if len(servers) != 1:
            raise InputError(f"服务器证书文件必须恰好包含 1 张证书，实际 {len(servers)} 张")
        ee = servers[0]

        intermediates: list = []
        for path in args.intermediate:
            intermediates.extend(load_cert_file(path))
        # 去重后仍超限则报错
        unique_digests = {cert_sha256(c) for c in intermediates}
        if len(unique_digests) > MAX_INTERMEDIATES:
            raise InputError(
                f"中间证书去重后共 {len(unique_digests)} 张，"
                f"超过上限 {MAX_INTERMEDIATES} 张"
            )

        # 固定锚：必须与调用方给出的 DER 摘要逐位一致
        pin = args.pin.strip().lower().replace(":", "").replace(" ", "")
        try:
            int(pin, 16)
        except ValueError:
            raise InputError("--pin 必须是十六进制 SHA-256 摘要")
        anchor_digest = cert_sha256(anchor)
        if pin != anchor_digest:
            raise InputError(
                f"锚固定值不符：参数给出 {pin}，"
                f"实际锚 DER 摘要为 {anchor_digest}"
            )

        # 全部输入证书都必须落在受限档位内
        check_static_profile(anchor, "信任锚")
        check_static_profile(ee, "服务器证书")
        for idx, c in enumerate(intermediates):
            check_static_profile(c, f"中间证书[{idx}]")

        candidates = build_candidates(anchor, ee, intermediates, target_dns, at_time)
    except InputError as exc:
        print(f"输入错误: {exc}", file=sys.stderr)
        return 2
    except ProfileError as exc:
        print(f"证书档位不合规: {exc}", file=sys.stderr)
        return 2
    except X509VerifyError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    valid = [c for c in candidates if c.valid]
    invalid = [c for c in candidates if not c.valid]

    if valid:
        # 唯一展示路径：candidates 已按摘要序列排序，取最小者
        chosen = valid[0]
        path = [_cert_node(cert, depth) for depth, cert in enumerate(chosen.chain)]
        result = {
            "trusted": True,
            "targetDns": target_dns,
            "atTime": at_time.isoformat(),
            "anchorPin": pin,
            "validChainCount": len(valid),
            "path": path,
            "otherCandidatesFirstFailures": [
                c.failure.to_dict() for c in valid[1:]
            ],
        }
        if args.as_json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"结论: 接受（存在 {len(valid)} 条合法候选链）")
            print(f"目标 DNS 名: {target_dns} @ {at_time.isoformat()}")
            print("展示路径（按证书 DER 摘要序列确定）:")
            for node in path:
                print(f"  [{node['depth']}] {node['sha256']}  {node['subject']}")
        return 0

    # 无合法链：列出各候选首先失败的证书与约束（按摘要序列稳定排序）
    failures = []
    for c in invalid:
        if c.failure is not None:
            entry = c.failure.to_dict()
            entry["chain"] = [
                _cert_node(cert, depth)
                for depth, cert in enumerate(c.chain)
            ]
            failures.append(entry)

    result = {
        "trusted": False,
        "targetDns": target_dns,
        "atTime": at_time.isoformat(),
        "anchorPin": pin,
        "candidateCount": len(invalid),
        "candidatesFirstFailures": failures,
    }
    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("结论: 拒绝（不存在合法链）")
        print(f"目标 DNS 名: {target_dns} @ {at_time.isoformat()}")
        print(f"候选路径数: {len(invalid)}，各候选首个失败如下：")
        for i, f in enumerate(failures):
            print(f"  候选 #{i + 1}: 失败证书 sha256={f['sha256']} "
                  f"subject={f['subject']}")
            print(f"      约束={f['reason']}  细节={f['detail']}")
    return 1


def main() -> None:  # console_scripts 入口
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # 未预期异常：内部错误
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
