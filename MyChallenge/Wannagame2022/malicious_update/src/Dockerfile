FROM python:3.7

RUN pip install --no-cache-dir gunicorn

COPY app/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY app /app
COPY flag.txt /flag.txt
RUN chmod 755 /app
RUN chmod 755 /app/*
RUN chmod 744 /flag.txt

RUN useradd -s /bin/bash ctf
USER ctf
WORKDIR /app


ENTRYPOINT ["./gunicorn.sh"]