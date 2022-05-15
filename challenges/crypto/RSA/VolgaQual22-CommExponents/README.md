# Communicating Exponents
author: [mahaloz (Zion Basque)](https://mahaloz.re)
ctf: Volga Quals 2022

## Summary
A challenge that gives only a public key and an encrypted file. The `e` associated with the public key is rather larger, which indicates that the `d` is small. A large `e` is usually an indicator that you can crack the private key `d` using wieners attack, but the d is not small enough in this case. Using an extended version of wieners attack, Boneh Durfee, we can derive the small `d` from the large `e` and `N`. See script for use of LLL. 

## Challenge Files
The challenge provides three files:
- encrypt.sh: the way they called openssl with the pubkey
- rsa_pub.pem: the public key used for encryption
- flag.enc: the encrypted flag file 

## Solution
In my solution I provide a `solve.sage` script and a `Dockerfile` to run it in. The Dockerfile is really just a way to make sure the user has SageMath 9.5 installed and pycryptodome for their python.

The script mostly uses the work done from [this repo](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage), but with new constants we use for solving. I've packaged the script more into a function `boneh_durfee_attack(N, e)` that should be easily callable now for quick attacks when you only have an `N` and `e`.

The big indicator for this challenge is that `e` is so large:
```python
[nav] In [1]: from Crypto.PublicKey import RSA

[nav] In [2]: f = open('rsa_pub.pem','r')

[nav] In [3]: key = RSA.import_key(f.read())

[ins] In [4]: key.e
Out[4]: 509400401183993386598745991841695789965803577018496383973610712015390731952573188892607068365045750956220514439318420820414674457717326610021697773025034023029106539445589380601502110309168017135751408755233566808484079679030884201065957896422213752055277177097935656421755231895714928093448868109156498366044486135035000248179690996646026809626974650538004341731057827787632279121306065487494611608226671415435208508448888705165570622606586815577489805929822189113929662282665193744133120319820122535526728275841105116073019206852443361320494448818509280320727111572056547660440166869901028959846637388604855898329
```

In a normal use of RSA, the `e` will:
1. not be _that_ large (normal value is 66537)
2. be a prime or co-prime to phi(N) 

With this information I was able to google around until I found the blog about Boneh Durfee by [David](https://www.cryptologie.net/article/241/implementation-of-boneh-and-durfee-attack-on-rsas-low-private-exponents/). 

From that point it was just using the solution script. 



