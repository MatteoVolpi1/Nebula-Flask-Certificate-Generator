# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app/api

# Copy the Flask API files to the working directory
COPY . .

# Install dependencies (such as wget and tar)
RUN apt-get update && apt-get install -y wget tar && apt-get clean

# Download Nebula tarball and extract it
RUN wget https://github.com/slackhq/nebula/releases/download/v1.7.2/nebula-linux-amd64.tar.gz && \
    tar -xzf nebula-linux-amd64.tar.gz -C /usr/local/bin && \
    rm nebula-linux-amd64.tar.gz

# Install the necessary dependencies
RUN pip install flask werkzeug

# Expose the port where the Flask API will run
EXPOSE 5000

# Command to run the Flask API
CMD ["python", "app.py"]
