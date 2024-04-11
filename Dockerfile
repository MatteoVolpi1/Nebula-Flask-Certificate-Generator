# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app/api

# Copy the Flask API files to the working directory
COPY . .

# Install Flask and any other necessary dependencies
RUN pip install flask

# Expose the port where the Flask API will run
EXPOSE 5000

# Command to run the Flask API
CMD ["python", "app.py"]