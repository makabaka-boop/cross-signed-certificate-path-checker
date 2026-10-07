# x509verify —— 受限离线 X.509 路径验证

一个**刻意收窄输入域**、裁决逻辑自研的 X.509 路径验证命令行工具，外加
Compose 离线验证入口。针对的核心问题：

> 同名 CA 可以持有不同密钥、互相交叉签发。遇到“第一张发行者”就停下，
> 既会**拒绝合法链**（真正签名成立的发行者排在后面），也可能
> **绕过另一条链上的域名约束**（选错分支）。

本工具因此枚举**所有签名实际成立**的候选链，对每条独立做
RFC 5280 语义验证；任一分支的名称约束不会泄漏到另一分支。

## 输入与输出

| 项 | 说明 |
|---|---|
| 信任锚 | 单张证书，用 `--pin` 固定其 **DER 的 SHA-256**；文件内容被替换即退出码 2 |
| 服务器证书 | 单张（PEM 或 DER） |
| 中间证书 | **无序**、合计去重后 **至多 8 张**；每个文件可含单张 DER、单张 PEM 或串联多张 PEM |
| 验证时刻 | ISO-8601（`2026-06-01T00:00:00Z`），比较按 UTC |
| DNS 名 | **精确** ASCII 名，小写匹配；不支持 IDNA/通配符 |

退出码：

* `0` 存在合法链；输出按**证书 DER 摘要序列**确定的唯一展示路径；
* `1` 输入有效但**不存在**合法链；列出每条候选链**首先失败的证书与约束**；
* `2` 用法/输入错误（锚固定值不符、超过 8 张中间证书、证书超出受限档位）；
* `3` 内部错误。

## 受限档位（超出即退出码 2，不进入链裁决）

* 证书签名算法只接受 `ecdsa-with-SHA256`，主体公钥只接受 **P-256 (secp256r1)**；
* DNS 名只接受 ASCII；`subjectAltName` 与 `nameConstraints` 只能含
  `dNSName`（出现 IP/email/URI 等即拒）；
* 出现**本工具未实现语义的 critical 扩展一律拒绝**（RFC 5280 §4.2）；
* 不做撤销（CRL/OCSP）、证书策略（policy mapping/anyPolicy）、通配符、
  AIA/CA-issuers 抓取、IDNA；
* `cryptography` 仅用于证书**解析/编码**与**单张** ECDSA 验签，
  **绝不调用其完整路径验证器**（`verify_*`/`VerificationModel` 等）代为裁决。

## RFC 5280 语义（在自研代码中实现，见 `x509verify/validate.py`）

仅对“签名已逐跳成立”的候选链顺序检查：

1. **有效期**：锚豁免，其余证书 `notBefore ≤ t ≤ notAfter`（边界闭区间）；
2. **CA/KeyUsage**：中间证书必须 `cA=TRUE` 且 KU 含 `keyCertSign`；
   EE 不得 `cA=TRUE`/`keyCertSign`，且 KU（若有）须含 `digitalSignature`；
3. **serverAuth 用途逐层传播**（§4.2.1.12）：链上某张 CA 一旦带 EKU，
   其后每张证书都必须带 EKU，逐层取交集并正确处理 `anyExtendedKeyUsage`
   通配符；EE 的有效用途必须含 `serverAuth`；
4. **pathLenConstraint**：对每个上层 CA 单独累计其下方的非 self-issued
   中间 CA 数，超限即失败；
5. **名称约束累计**：每深入一层先并入发行者的 NC，再检查该证书 SAN 中的
   **全部** DNS 名（中间 CA 的 SAN 也受约束，不只是叶子）；
   permitted 逐层取交集、excluded 累计并集；`.example.com` 覆盖顶点与子域，
   裸 `example.com` 只精确匹配；防止 `notexample.com` 这类后缀拼接绕过；
6. **self-issued 换钥**（§4.2.1.9/§6.1）：subject 与 issuer 同名但
   由**另一把同名密钥**签发的节点正常向上验签、计入链，但
   **不能当作自签可信根**；pathLen 计数时按规范豁免；
7. **锚自身豁免**：锚的自签签名与有效期不参与本次链验证，但锚仍须满足
   受限档位（P-256/SHA256 等），且 DER 摘要必须与 `--pin` 完全一致。

## 候选链建立（`x509verify/chain.py`）

* DFS 从 EE 向上，发行关系需同时满足：发行者主体名 == 子证书发行者名、
  AKI/SKI 兼容（若二者都存在）、**单张验签实际成立**；
* 路径按证书 DER 摘要去重，**防止证书环**；自签边（self-issued 且能被
  自己公钥验签）不扩展，self-issued **换钥**边不会被误跳过；
* 只有被 `--pin` 固定的那一张锚能终止链；中间证书池里混入其它自签根
  不会被当作锚；
* 候选与展示路径均按 DER 摘要序列排序——**输入中间证书的任意排列
  不改变枚举集合、信任结论与展示路径**。

## 命令行用法

```sh
python -m x509verify \
  --anchor root.pem \
  --pin 4e72c348615b72963d913624f34945fd41eedbc88840b16b4baa587ef9faaf64 \
  --server leaf.pem \
  --intermediate ca-under-a.pem --intermediate ca-under-b.pem \
  --at-time 2026-06-01T00:00:00Z \
  --name www.example.com [--json]
```

拒绝时（退出码 1）JSON 的 `candidatesFirstFailures` 给出每条候选链首个失败：
证书 DER 摘要、subject、失败约束（`expired`/`notCA`/`keyUsage`/
`nameConstraints_permitted`/`nameConstraints_excluded`/`ekuServerAuth`/
`pathLenExceeded`/`issuerNotFound` …）与可读细节。

## Compose 离线入口

镜像唯一第三方依赖是 `cryptography`；compose 服务 `network_mode: "none"`，
无任何出站连接。

```sh
docker compose build verifier
PIN_ROOT_B=$(awk -F'= ' '/root-b.pem/{print $2}' demo/pins.txt) \
  docker compose run --rm cross-good    # 接受，exit 0
PIN_ROOT_A=$(awk -F'= ' '/root-a.pem/{print $2}' demo/pins.txt) \
  docker compose run --rm cross-bad     # 拒绝，exit 1（NC 排除）
PIN_ROLLOVER_ROOT=$(awk -F'= ' '/root.pem/{print $2}' demo/pins.txt) \
  docker compose run --rm rollover     # 换钥链，接受，exit 0
```

通用入口 `verifier` 通过环境变量 `ANCHOR/PIN/SERVER/INTERMEDIATES/
AT_TIME/NAME` 接收参数（包装脚本见 `scripts/verify.sh`）。
无容器时可直接跑 `./scripts/demo.sh` 复现同样四种结论。

## 演示拓扑（`demo/`，由 `scripts/make_demo_pki.py` 生成）

* **交叉签发**：`root-a`/`root-b` 同名 "Shared Root"、不同密钥；
  同主体同公钥的 `Edge CA` 被两把根分别签成两张不同 DER 的 CA 证书。
  root-a 版本带 `excludedSubtrees=.example.com`（坏分支），root-b 版本无
  约束（好分支）。固定不同锚，信任结论不同，且中间证书包里混入的另一把
  根不会被误信；
* **换钥**：自签锚（旧钥）→ self-issued 换钥证书（新公钥、旧钥签名）→
  换钥后 ICA → leaf。

## 测试

```sh
python -m pytest -q
```

测试覆盖：同名不同钥、先坏后好交叉链与回溯、互签环防死循环、
嵌套 permitted 交集/excluded 累计、中间 CA SAN 同样受约束、跨分支
约束不泄漏、self-issued 换钥与 pathLen 豁免、未固定的换钥节点不得当根、
EKU 跨层传播与 ANY 通配、有效期边界、锚签名/有效期豁免、未知 critical
扩展、非 DNS SAN、通配符与 ASCII 拒绝、pin 不符、DER/串联 PEM 输入、
以及多种输入排列下信任结论与展示路径完全不变。

## 代码结构

```
x509verify/
  errors.py      异常与退出码
  certutil.py    加载/DER 摘要/扩展读取/单张 ECDSA 验签（无路径裁决）
  dnsnames.py    ASCII 规范化与名称约束匹配
  profiles.py    受限静态档位检查（算法/曲线/critical/SAN/NC 形状）
  validate.py    单条已成立候选链的 RFC 5280 语义裁决
  chain.py       无序中间证书枚举、逐跳验签、防环、锚终止、候选排序
  cli.py         命令行（pin 固定、报告、退出码）
tests/           pytest：certfactory 构造拓扑的用例
scripts/         verify.sh（容器入口）、demo.sh、make_demo_pki.py
docker-compose.yml / Dockerfile   离线 Compose 入口
```
