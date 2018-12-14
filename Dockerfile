FROM ubuntu:18.10

ARG LANG=C.UTF-8
ARG LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y python3-dev python3-pip libev-dev
RUN pip3 install pipenv

COPY . /app

WORKDIR /app
RUN pipenv install

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

CMD ["pipenv", "run", "python", "run.py"]

