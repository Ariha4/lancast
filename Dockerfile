# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Install the package (and its test extra) from pyproject.toml
COPY pyproject.toml README.md ./
COPY lancast ./lancast
COPY tests ./tests

RUN pip install --no-cache-dir .[dev]

# Run the test suite at build time so a broken image never ships
RUN pytest -q

# LANCast's two real network surfaces:
#   50999/udp - peer discovery beacon (broadcast)
#   51000/tcp - file transfer server (default, overridable via --port)
EXPOSE 50999/udp
EXPOSE 51000/tcp

VOLUME ["/received"]

ENTRYPOINT ["lancast"]
CMD ["serve", "--dest", "/received", "--port", "51000"]