FROM python:3.12.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER appuser
EXPOSE 8000
CMD ["uvicorn", "agent_guard_eval.api:app", "--host", "0.0.0.0", "--port", "8000"]
