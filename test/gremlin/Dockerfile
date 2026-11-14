# Gremlin Server for the graph-queries job. Neptune engine 1.4.7.0 supports
# Gremlin 3.7.1 only, and upstream has no 3.7.1 build with a fixed trust store,
# so upgrade ca-certificates from the Alpine security repo (CVE-2026-111943).
FROM docker.io/tinkerpop/gremlin-server:3.7.7@sha256:afc395b5e96cfeea72b6d0b59d22ad5cee502c31bfdad6f4d3b2de070d905e0f

USER root
RUN apk add --no-cache --upgrade ca-certificates ca-certificates-bundle \
 && update-ca-certificates \
 && installed="$(apk list --installed ca-certificates | sed -n 's/^ca-certificates-\([^ ]*\) .*/\1/p')" \
 && echo "ca-certificates $installed" \
 && test "$(apk version -t "$installed" 20261020-r0)" != "<"
USER gremlin
