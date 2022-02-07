# Challenges
## Table of Contents
- [pwn](./pwn)
    - [heap](./pwn/heap): exploitation that occurs mainly utilizing the heap. 
        - [tcache](./tcache)

- [rev](./rev) 
    - [json](./rev/json): JSON file manipulation

## Organization
Instead of grouping things by CTF or year, let's group things by concept and topic.
Example:
- pwn
    - heap
        - tcache
    - kernel
        - ret2user

- rev
    - Virtual Machines
    - Packers
        - udp

- crypto
    - ECC 
    - RSA
        - small exponent attack

- misc
    - Stego

### Writeup Format
1. Have the solve script/files
2. Have a writeup
    - The writeup must have a `## Summary` that gives the jist of what happen.
        - Example: "Exploing a use-after-free in libc 2.31 using house of BotCake"

