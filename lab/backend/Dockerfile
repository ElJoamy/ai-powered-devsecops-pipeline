FROM python:3.12-slim

# Educational Docker misconfigurations: USER and HEALTHCHECK omitted on purpose.
# Build context: backend/. Never copy the vulnerability fixtures into this image.
WORKDIR /lab
ENV PYTHONDONTWRITEBYTECODE=1
COPY app.py ./app.py
CMD ["python", "-B", "app.py"]
