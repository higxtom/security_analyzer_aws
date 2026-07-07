FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

# AgentCore Runtime の A2A プロトコル契約により、ポートは 9000 固定
ENV HOST=0.0.0.0
ENV PORT=9000
ENV PYTHONUNBUFFERED=1

EXPOSE 9000

ENTRYPOINT ["python", "-m", "src.agent.agentcore_app"]
