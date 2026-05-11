# syntax=docker/dockerfile:1

FROM python:3.13-slim

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install curl so we can fetch uv, then install uv
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

# Copy dependency metadata, license, readme and source
COPY pyproject.toml LICENSE README.md ./
COPY src/ ./src/

# Copy the demo application
COPY demo/ ./demo/

# Install the package in editable mode with dev extras
RUN uv pip install --system -e ".[dev]"

WORKDIR /app/demo

EXPOSE 8000

ENTRYPOINT ["sh", "/app/demo/entrypoint.sh"]
CMD ["runserver", "0.0.0.0:8000"]
