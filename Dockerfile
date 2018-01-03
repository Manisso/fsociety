# Use Python 2.7 Slim
FROM python:2.7-slim

# Update Repos
RUN apt-get update && apt-get install -qq -y --no-install-recommends \
    build-essential git sudo wget curl

# Install Python dependecies
RUN pip install requests

# Git fsociety
RUN git clone https://github.com/Manisso/fsociety.git

# Install fsociety
RUN cd fsociety && chmod +x install.sh && ./install.sh

# Remove fsociety install folder
RUN rm -rf fsociety

# Run fsociety
RUN fsociety
