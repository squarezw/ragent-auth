#!/bin/sh
# Install only during the approved TLS rollout. Other certificates do not reload.
set -eu
case " ${RENEWED_DOMAINS:-} " in
  *" {{ISSUER_HOST}} "*)
    /usr/sbin/nginx -t
    /usr/bin/systemctl reload nginx
    ;;
  *) exit 0 ;;
esac
