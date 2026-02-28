# Pin exact digest so every build uses an identical base layer.
# To refresh: docker pull python:3.11-slim && docker inspect python:3.11-slim --format '{{index .RepoDigests 0}}'
FROM python:3.11-slim@sha256:c8271b1f627d0068857dce5b53e14a9558603b527e46f1f901722f935b786a39

LABEL maintainer="KEVGraph Research"
LABEL description="Reproducible pipeline for KEVGraph paper"

# System deps for PuLP CBC solver
RUN apt-get update && \
    apt-get install -y --no-install-recommends coinor-cbc && \
    rm -rf /var/lib/apt/lists/*

# Non-root user — never run research pipelines as root
RUN useradd --uid 1000 --create-home --shell /bin/bash kevgraph

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Hand off ownership before switching user
RUN chown -R kevgraph:kevgraph /app

USER kevgraph

# Data volume mount point
VOLUME /app/data

# GITHUB_TOKEN must be passed at runtime:
#   docker run -e GITHUB_TOKEN="ghp_..." kevgraph
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.pipeline"]
CMD []
