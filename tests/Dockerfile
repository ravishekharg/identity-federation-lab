FROM python:3.12-slim
RUN pip install --no-cache-dir requests==2.32.3
COPY e2e.py /e2e.py
CMD ["python", "-u", "/e2e.py"]
