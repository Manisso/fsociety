# Download base image ubuntu 16.04
FROM ubuntu:16.04

# Update Ubuntu Software repository
RUN apt-get update && apt-get -y upgrade

# Install Python 2.7 & Git
RUN apt-get install wget git python2.7 python-pip

# Install Pip Requirements
RUN pip install requests beautifulsoup4

# Install fsociety
RUN wget https://github.com/Manisso/fsociety/blob/master/install.sh && chmod +x install.sh && ./install.sh

# Run fsociety
RUN fsociety
