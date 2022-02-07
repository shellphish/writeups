# Hyperlink (71 solves/ 142 points)
## Description
I made a really fun game! Can you link up the chain to reach the destination?

## Solution
I started by opening up the attached ``.json`` file. It looked really confusing at first but
after looking at it for a bit I made some key observations. The data structure primarily built
around the ``links`` dictionary. There is a key for all of the lowercase letters in the alphabet
along with ``_``, ``{``, and ``}``. This is the alphabet for a flag! Each value is a **VERY** long
list of numbers. Each of those numbers decreases in size with the exception of random a random
``0`` here and there. There was also a ``start`` and ``target`` value. Each was a large number.

At this point I was familiar enough with the ``.json`` that I was ready to take a look at the
attached ``app.py`` file. The python file starts by loading in the ``.json`` file. It asks for
a chain from user input. It checks to make sure that the supplied characters are in the set of
valid characters. (The same ones that are in the ``.json``) It breaks our input down from a string
to a list of chars. It then calls the ``test_chain()`` function. If it returns ``True``, we get
congratulated, if it returns ``False`` we get an error. At this point I realized that there is no
``nc`` server for this chall and the code has no mechanism for giving you a flag. I made the
assumption that there is only one valid chain that fits the flag format, and that the chain that
works would be the flag. I know needed to analyze the ``test_chain()`` function to see what the goal
was.

```python
def test_chain(links, start, end):
    current = start
    for link in links:
        current = int(''.join(
            str(int(current & component != 0))
            for component in link
        ), 2)
    return end == current & end
```

This function is given the input list of chars as ``links``, the ``start`` value of the ``.json``,
and the ``target`` of the ``.json``. It sets a var ``current`` equal to our starting point, then
performs some operations with every link in our proposed chain. Upon further inspection, I found
that it bitwise ANDs every value in the current char with the value we have stored in ``current``.
If the result of the AND is 0, then we append a ``0`` to a string, if not, a ``1`` gets appended.
After all these 1's and 0's get appended together, they get interpreted as a binary number and that
number becomes our new ``current`` value. If after we repeat this process for every link in our chain
and the result is the ``target`` value, we know we have a flag.

I was pretty stuck at this point. I was looking at the files in the ``.json`` and noticed that the
values for each character were **incredibly** similar. I decided to write a script to try one character
at a time and look at the binary. The very strange thing I noticed was that only one character produced a
different binary string than the others. I built off my script and wrote it so that starting at any given prefix,
which I set to ``dice{`` as the start becuase I knew it would be the flag, the script would look for the character
that produced a new result, and then append it to the prefix an repeat. This worked... kind of.

I supplied ``dice{`` and got back ``dice{evera`` I looked like it was giving some part of the flag. I messed around
with bruteforcing ``prefix`` possiblilities and got a few flag leaks. Below are the most notable:

```
prefix = 'flag'
flag_is_lineara
prefix = 'alg'
algebra}
prefix = 'dice{'
dice{evera
```
Ok... so the longest leak I got was ``flag_is_lineara``. Another important find is that ``algebra}`` ends in a ``}``.
This means that it is the end of the flag. I though at first that ``flag_is_lineara`` would be in the flag, but later
I realized that the ``flag`` portion was the prefix and would always exhist in the output. The only confirmed info the
leak gives is ``_is_linear``, ``dice{evera``, and ``ebra}``. Using common sense I narrowed it down to this format:
``dice{ever??????_is_linear_algebra}``. I looked on google for words starting with ever and saw everything. This made
sense with the rest of what I knew so I plugged it in and sure enough, it was the correct flag!!!

Certainly not the most elegant solution but the following the patterns still led me to the flag in the end. I can only
assume from the flag that the intended solution was much prettier using some linear algebra goodies, but whatever works.
## Flag
``dice{everything_is_linear_algebra}``
