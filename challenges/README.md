# Challenges
## Table of Contents
- [pwn](./pwn)
    - [heap](./pwn/heap): exploitation that occurs mainly utilizing the heap. 
        - [tcache](./tcache)

- [rev](./rev) 
    - [json](./rev/json): JSON file manipulation
    - [golang](./rev/golang): Mostly reversing Go stuff
    - [motorolla](./rev/motorolla): Reversing Motorolla variant archs 

- [crypto](./crypto)
    - [ECC](./crypto/ECC): Eliptic Curve Crypto
    - [RSA](./crypto/RSA): RSA and RSA-Like Crypto Schemes

## Organization
Group challenges by topic and solution, not by their CTF. If there are multiple topics in a single challenge, group the challenge by the hardest concept. For instance, if you have a Go reversing binary that had a small RSA crypto scheme implemented in it, if the majorigy of the challenge was reversing then group it as reversing. 

### Writeup Format
1. A README.md
    - Should contain a Summary section that very breifly explains the challenge, solution, and how you might spot this problem in the future 
        - Example: "Exploing a use-after-free in libc 2.31 using house of BotCake"
    - (optional) Should contain a description of the challenge files and provided solution files
    - (optional) A longer writeup of the challenge 

2. Solution files
3. (optional) Challenge files and way to reproduce and run it
    - Would be nice if you had a Dockerfile 
