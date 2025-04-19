# This dockerfile builds the SOAR Lite stable release
FROM python:3.10-slim
LABEL maintainer="Renato Kopke <renatokopke@gmail.com>"

WORKDIR /app

COPY . /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "core.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]