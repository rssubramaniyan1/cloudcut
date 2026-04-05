FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt mcp

COPY . .

ENV CLOUDCUT_TRANSPORT=http
ENV PORT=8000

EXPOSE 8000

CMD ["python", "-m", "cloudcut.cloudcut_mcp_server"]
