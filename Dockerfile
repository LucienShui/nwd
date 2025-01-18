FROM python:3-alpine
COPY ./ /app
WORKDIR /app
CMD ["python3", "cron.py"]
