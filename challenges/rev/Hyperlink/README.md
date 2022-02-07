# Hyperlink (71 solves/ 142 points)
## Description
I made a really fun game! Can you link up the chain to reach the destination?

##Solution
I started by opening up the attached ``.json`` file. It looked really confusing at first but
after looking at it for a bit I made some key observations. The data structure primarily built
around the ``links`` dictionary. There is a key for all of the lowercase letters in the alphabet
along with ``_``, ``{``, and ``}``. This is the alphabet for a flag! Each value is a VERY long
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
