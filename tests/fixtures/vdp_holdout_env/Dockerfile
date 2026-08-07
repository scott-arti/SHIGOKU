# SGK-2026-0423 Lane P-2 — opaque holdout fixture target image.
# Copies ONLY the fixture file (no fixed routes — routes are random at
# runtime, so the image is safe to build and reuse).
FROM python:3.13-slim
WORKDIR /app
COPY holdout_fixture_target.py /app/holdout_fixture_target.py
EXPOSE 8000
CMD ["python", "holdout_fixture_target.py"]
