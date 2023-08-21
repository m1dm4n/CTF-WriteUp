FROM ubuntu:22.04

USER root:root
RUN apt-get update
RUN apt-get install -y python3 python3-pip socat bc git
RUN python3 -m pip install pycryptodome pyseccomp

RUN adduser itstime
RUN mkdir /itstime
ADD . /itstime
RUN chmod -R 666 /itstime

WORKDIR /
RUN git clone https://github.com/wolfcw/libfaketime.git
WORKDIR /libfaketime/src
RUN make install

WORKDIR /itstime
EXPOSE 31339
CMD rm -rf /dev/urandom;   \
    touch /dev/urandom;    \
    su -c 'socat                                     \
              -T 600                                 \
              -d -d TCP-LISTEN:31339,reuseaddr,fork  \
           EXEC:"/bin/bash ./start.sh"'              \
       -s /bin/bash itstime