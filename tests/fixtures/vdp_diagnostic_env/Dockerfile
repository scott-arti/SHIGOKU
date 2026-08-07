# SGK-2026-0425 M4 — generated opaque diagnostic fixture target image.
# Copies ONLY the fixture file (no fixed routes — routes/fields/ids are
# generated at runtime from DIAG_SEED, so the image is safe to build and
# reuse). Standard library only; no pip installs.
FROM python:3.12-slim
WORKDIR /app
COPY fixture_target.py /app/fixture_target.py
EXPOSE 8000
CMD ["python", "/app/fixture_target.py"]
