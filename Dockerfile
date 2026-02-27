FROM python:3.11-slim

LABEL maintainer="KEVGraph Research"
LABEL description="Reproducible pipeline for KEVGraph paper"

# System deps for PuLP CBC solver
RUN apt-get update && \
    apt-get install -y --no-install-recommends coinor-cbc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Data volume mount point
VOLUME /app/data

# GITHUB_TOKEN must be passed at runtime:
#   docker run -e GITHUB_TOKEN="ghp_..." kevgraph
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.pipeline"]
CMD []
