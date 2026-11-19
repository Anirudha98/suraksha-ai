# One container: builds the React UI, then serves it + the FastAPI API.
FROM node:20-slim AS ui
WORKDIR /ui
COPY newcrime/frontend/package*.json ./
RUN npm ci
COPY newcrime/frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
COPY newcrime/backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY newcrime/backend/ ./
COPY --from=ui /ui/dist ./static
ENV PORT=8000
CMD uvicorn app.main:app --host 0.0.0.0 --port $PORT
