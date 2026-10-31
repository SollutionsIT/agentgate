FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913 AS build
WORKDIR /build
RUN pip install --no-cache-dir uv==0.12.19
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --compile-bytecode

FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913
RUN groupadd --gid 10001 agentgate && useradd --uid 10001 --gid agentgate --no-create-home agentgate
WORKDIR /app
COPY --from=build /build/.venv /build/.venv
COPY examples /app/examples
ENV PATH="/build/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "agentgate.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--limit-concurrency", "100", "--timeout-keep-alive", "5"]
