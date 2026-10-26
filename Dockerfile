FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

USER root
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends xvfb xauth \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py dashboard.py admin_auth.py config.example.json accounts.example.txt ./
COPY static ./static

ENV CPA_HELPER_CONFIG=/app/config.json
ENV CPA_VIRTUAL_DISPLAY=1
EXPOSE 8765
CMD ["sh", "-c", "Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp & export DISPLAY=:99; exec python app.py --config /app/config.json"]
