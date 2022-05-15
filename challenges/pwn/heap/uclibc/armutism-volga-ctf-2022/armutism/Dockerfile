FROM kalilinux/kali-rolling

RUN apt-get update
RUN apt-get install -y qemu-user socat

COPY src/build/ld-uClibc.so.0 /lib/
COPY src/build/libc.so.0 /lib/
COPY src/build/armutism /task/
COPY src/sh /task/
COPY src/flag.txt /tmp/flag.txt

RUN chmod 0444 /tmp/flag.txt

CMD ["socat", "-T 30", "tcp-l:1337,reuseaddr,fork", "EXEC:\"/task/sh\",pty,stderr"]
EXPOSE 1337
