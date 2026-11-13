# Demo protected app (the "internal-api" the tunnel reaches).
#
# target_service.py is stdlib only (argparse, json, socket, threading,
# http.server), so there is nothing to pip-install -- the image is just
# Python plus the one file.
FROM python:3.12-slim

WORKDIR /app

COPY target_service.py .

# 8080 is the internal-api target in identity.py APP_TARGETS.
EXPOSE 8080

# Plain HTTP mode (JSON answers). Add --hold to keep connections open instead
# -- that is the mode demo_e2e.sh uses to prove live-tunnel revocation.
CMD ["python", "target_service.py", "--port", "8080"]
