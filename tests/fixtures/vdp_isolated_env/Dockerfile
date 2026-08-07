# Lane O-1 disposable verification stack base image — SGK-2026-0423.
# Shared by all three services (CMD is overridden per service in the
# compose file). The runtime/evaluator services only use the base Python
# interpreter; the project venv and the host uv-python tree are bind-
# mounted at their absolute paths by docker-compose.yml.
FROM python:3.13-slim
WORKDIR /app
COPY fixture_target.py /app/fixture_target.py
EXPOSE 8000
CMD ["python", "/app/fixture_target.py"]
