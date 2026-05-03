FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.3 gunicorn==23.0.0 requests==2.32.3

COPY app.py ./

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
