FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy dependencies first (for caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of app
COPY . .

# Expose port (Render expects 10000 by default)
EXPOSE 10000

# Start server
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]