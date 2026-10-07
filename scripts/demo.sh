#!/bin/sh
# 本地（无容器）跑通三个演示场景，验证退出码与信任结论。
set -eu
cd "$(dirname "$0")/.."

PA=$(awk -F'= ' '/root-a.pem/{print $2}' demo/pins.txt)
PB=$(awk -F'= ' '/root-b.pem/{print $2}' demo/pins.txt)
PR=$(awk -F'= ' '/root.pem  /{print $2}' demo/pins.txt)
AT=2026-06-01T00:00:00Z

run_case() {
    name=$1; expect=$2; shift 2
    set +e
    ANCHOR=$ANCHOR PIN=$PIN SERVER=$SERVER INTERMEDIATES="$INTERMEDIATES" \
        AT_TIME=$AT NAME="$NAME" scripts/verify.sh >/tmp/x509v.out 2>/tmp/x509v.err
    rc=$?
    set -e
    if [ "$rc" -eq "$expect" ]; then
        echo "PASS $name (exit=$rc)"
    else
        echo "FAIL $name: expected exit $expect got $rc" >&2
        cat /tmp/x509v.out /tmp/x509v.err >&2
        exit 1
    fi
}

# 1) 固定好分支锚 root-b -> 接受 (0)
ANCHOR=demo/cross/root-b.pem PIN=$PB SERVER=demo/cross/leaf-example.pem \
INTERMEDIATES=demo/cross/intermediates.pem NAME=www.example.com \
run_case cross-good 0

# 2) 同样输入固定坏分支锚 root-a -> 拒绝 (1)，首个失败为 NC 排除
ANCHOR=demo/cross/root-a.pem PIN=$PA SERVER=demo/cross/leaf-example.pem \
INTERMEDIATES=demo/cross/intermediates.pem NAME=www.example.com \
run_case cross-bad 1

# 3) self-issued 换钥链 -> 接受 (0)
ANCHOR=demo/rollover/root.pem PIN=$PR SERVER=demo/rollover/leaf.pem \
INTERMEDIATES="demo/rollover/rollover-self-issued.pem demo/rollover/ica.pem" \
NAME=svc.example.org \
run_case rollover 0

# 4) 锚固定值不符 -> 输入错误 (2)
ANCHOR=demo/cross/root-b.pem PIN=$(printf '11%.0s' $(seq 1 32)) \
SERVER=demo/cross/leaf-example.pem \
INTERMEDIATES=demo/cross/intermediates.pem NAME=www.example.com \
run_case pin-mismatch 2

echo "全部演示场景通过"
