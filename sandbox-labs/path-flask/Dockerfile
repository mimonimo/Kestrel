FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.3 gunicorn==23.0.0

# Plant a canary file the path-traversal probe / payloads can read.
RUN mkdir -p /var/secret \
    && echo "kestrel-canary-secret" > /var/secret/flag.txt

COPY app.py ./

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
