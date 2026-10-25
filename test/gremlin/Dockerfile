# Gremlin Server for the graph-queries job. Neptune engine 1.4.7.0 supports
# Gremlin 3.7.1 only, and upstream has no 3.7.1 build with a fixed trust store,
# so upgrade ca-certificates from the Alpine security repo (CVE-2026-111943).
FROM docker.io/tinkerpop/gremlin-server:3.7.1@sha256:911e27acc8a43209fee272408fa99045f5ba48ae410c8cef6da8c500eca42416

USER root
RUN apk add --no-cache --upgrade ca-certificates ca-certificates-bundle \
 && update-ca-certificates \
 && installed="$(apk list --installed ca-certificates | sed -n 's/^ca-certificates-\([^ ]*\) .*/\1/p')" \
 && echo "ca-certificates $installed" \
 && test "$(apk version -t "$installed" 20261020-r0)" != "<"
USER gremlin
