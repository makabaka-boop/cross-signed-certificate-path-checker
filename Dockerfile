# 受限 X.509 路径验证工具 —— 离线镜像
# 构建后镜像内不含任何网络访问逻辑；验证全程不做撤销/策略/OCSP 查询。
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 仅安装唯一的第三方依赖（解析/单张验签用；禁止其完整路径验证器代裁决）
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY x509verify /app/x509verify
COPY scripts /app/scripts
COPY tests/certfactory.py /app/tests/certfactory.py
# 构建期生成只读演示 PKI 与 pins.txt（离线、无网络）
RUN python3 /app/scripts/make_demo_pki.py >/dev/null
COPY scripts/verify.sh /usr/local/bin/x509-verify
RUN chmod +x /usr/local/bin/x509-verify

# 离线包装入口（compose 默认使用；直接 docker run 可覆盖为 python -m x509verify）
ENTRYPOINT ["/usr/local/bin/x509-verify"]

