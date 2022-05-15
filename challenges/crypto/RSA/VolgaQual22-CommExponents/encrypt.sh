 #!/bin/sh

 openssl rsautl -encrypt -inkey rsa_pub.pem -pubin -in flag.txt -out flag.enc