FROM python:3.13-slim
WORKDIR /app
RUN apt-get update -q && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/app.py .
COPY index.html .
RUN mkdir -p /app/data /root/.ssh
COPY ssh/id_rsa_syslog /root/.ssh/id_rsa_syslog
RUN chmod 600 /root/.ssh/id_rsa_syslog
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--worker-class", "gthread", "--threads", "4", "--timeout", "600", "app:app"]
