#!/bin/sh
# 离线 X.509 路径验证入口。
#
# 环境变量（容器内 / compose 传入）：
#   ANCHOR         锚证书路径（PEM/DER，单张）             [必填]
#   PIN            锚 DER 的 SHA-256（hex，冒号/空格不敏感） [必填]
#   SERVER         服务器证书路径                          [必填]
#   INTERMEDIATES  无序中间证书路径，空格分隔（至多 8 张，可含串联 PEM）[可选]
#   AT_TIME        验证时刻 ISO-8601                       [必填]
#   NAME           精确 DNS 名（ASCII，不支持通配符）       [必填]
#
# 退出码透传：0 接受 / 1 无合法链 / 2 输入错误 / 3 内部错误。
set -eu

if [ -z "${ANCHOR:-}" ] || [ -z "${PIN:-}" ] || [ -z "${SERVER:-}" ] \
   || [ -z "${AT_TIME:-}" ] || [ -z "${NAME:-}" ]; then
    echo "用法：ANCHOR/PIN/SERVER/AT_TIME/NAME 为必填，INTERMEDIATES 可选" >&2
    exit 2
fi

set -- --anchor "$ANCHOR" --pin "$PIN" --server "$SERVER" \
       --at-time "$AT_TIME" --name "$NAME" --json

for f in $INTERMEDIATES; do
    set -- "$@" --intermediate "$f"
done

exec python3 -m x509verify "$@"
