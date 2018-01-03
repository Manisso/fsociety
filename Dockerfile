FROM python:2.7-slim

# run update
RUN apt-get update && apt-get install -qq -y --no-install-recommends \
    build-essential git sudo wget curl

# install python dependecies
RUN pip install requests

RUN git clone https://github.com/Manisso/fsociety.git

RUN cd fsociety && chmod +x install.sh && ./install.sh

RUN rm -rf fsociety

