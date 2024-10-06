ARG PYTHON_MAJOR_VERSION=3
ARG PYTHON_MINOR_VERSION=20
FROM python:alpine${PYTHON_MAJOR_VERSION}.${PYTHON_MINOR_VERSION}

COPY requirements.txt /tmp/requirements.txt

RUN apk add --no-cache \
    shadow \
    su-exec && \
    pip install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt && \
    mkdir -p /certificates && \
    addgroup -g 1000 cleanup && \
    adduser -D -H -G cleanup -u 1000 cleanup && \
    chown -R cleanup:cleanup /certificates

COPY src/ /app
COPY entrypoint.sh /usr/local/bin/entrypoint

ENV PUID=1000
ENV PGID=1000
ENV TRAEFIK_ACME_FILE=/certificates/acme.json
ENV CLEANUP_REPORT=/certificates/REPORT.md

# Build arguments for labels
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION
ARG REPO_URL

# Set labels
LABEL org.opencontainers.image.created=$BUILD_DATE \
    org.opencontainers.image.url=$REPO_URL \
    org.opencontainers.image.source=$REPO_URL \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.vendor="Aperim Pty Ltd" \
    org.opencontainers.image.title="Traefik acme.json cleaner" \
    org.opencontainers.image.description="Traefik acme.json cleaner"

# Set the entrypoint to the entrypoint script.
ENTRYPOINT ["/usr/local/bin/entrypoint"]

# Set the default command (can be overridden at runtime).
CMD ["/usr/bin/env", "python3", "/app/acme_cleanup.py"]
