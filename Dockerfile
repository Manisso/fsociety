FROM python:2.7-slim

# Update apt
RUN apt-get update && apt-get install -qq -y --no-install-recommends \
    build-essential git sudo wget curl

# Install python dependecies
RUN pip install requests

RUN git clone https://github.com/Manisso/fsociety.git

RUN cd fsociety && chmod +x install.sh && ./install.sh

RUN rm -rf fsociety

# Run fsociety
RUN fsociety
