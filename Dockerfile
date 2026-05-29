# Stage 1: Build the frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Build the backend and combine
FROM node:20-alpine
WORKDIR /app

# Copy backend files
COPY backend/package*.json ./backend/
COPY backend/scripts/ ./backend/scripts/
WORKDIR /app/backend
RUN npm install --omit=dev
COPY backend/ ./

# Copy frontend built assets to the expected relative location
WORKDIR /app
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose port
EXPOSE 5000

# Start server
WORKDIR /app/backend
CMD ["npm", "start"]
