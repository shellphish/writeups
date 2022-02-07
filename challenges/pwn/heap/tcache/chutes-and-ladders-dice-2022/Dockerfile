FROM ubuntu:focal-20220113

run apt-get -qq update && apt-get install -qq --no-install-recommends xinetd sudo

RUN mkdir /service
ARG THE_FLAG="dice{i_can't_be_riding_round_n_round_that_open_strip_c2f678198132}"
RUN touch /service/flag && chmod 644 /service/flag && echo $THE_FLAG > /service/flag

COPY chutes /service/chutes

copy docker/wrapper /wrapper
copy docker/service.conf /service.conf

expose 31326
cmd ["/usr/sbin/xinetd", "-filelog", "/dev/stderr", "-dontfork", "-f", "/service.conf"]
