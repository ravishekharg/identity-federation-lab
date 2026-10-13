FROM python:3.12-slim
RUN pip install --no-cache-dir requests==2.32.3 "PyJWT[crypto]==2.10.1"
COPY render.py /render.py
CMD ["python", "/render.py"]
