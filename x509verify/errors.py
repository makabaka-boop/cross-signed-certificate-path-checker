"""统一异常类型与常量。

退出码约定：
* 0  —— 存在合法链，已输出唯一展示路径
* 1  —— 输入合法，但不存在任何能成立的候选链（信任结论：拒绝）
* 2  —— 用法错误 / 输入本身不合格（锚固定值不符、证书档位不合规等）
* 3  —— 工具内部错误
"""


class X509VerifyError(Exception):
    """所有可预期错误的基类。"""


class InputError(X509VerifyError):
    """命令行输入不合法：文件读不出、DER/PEM 解析失败、锚固定值不符等。"""


class ProfileError(X509VerifyError):
    """证书档位不合规：非 P-256、未知 critical 扩展、SAN/NC 含非 DNS 项等。

    本工具的输入域被刻意收窄，档位不合规属输入错误（退出码 2），
    而不是“某条候选链失败”（退出码 1）。
    """


EXIT_OK = 0
EXIT_NO_VALID_CHAIN = 1
EXIT_INPUT_ERROR = 2
EXIT_INTERNAL = 3
