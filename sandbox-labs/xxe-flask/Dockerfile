FROM python:3.12-slim

WORKDIR /app

# lxml is the only realistic Python XML parser that exposes external
# entity resolution; built-in xml.etree refuses by default.
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==23.0.0 lxml==5.3.0

COPY app.py ./

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
