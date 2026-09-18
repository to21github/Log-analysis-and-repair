# 零第三方依赖，仅使用 Python 标准库，ARM 构建快、兼容性好
FROM python:3.12-alpine

COPY app /app

CMD ["python3", "-u", "/app/main.py"]
