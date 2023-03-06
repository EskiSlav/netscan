FROM python:3.11.0rc2-alpine3.16

WORKDIR /opt/opinov8bot/


RUN apk update \
    && apk add postgresql-dev gcc python3-dev musl-dev curl

COPY requirements.txt .

RUN python -m pip install -r requirements.txt

EXPOSE 8081

COPY . .

CMD ./run.sh
