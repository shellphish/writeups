import json

def chain(links, start):
    current = start
    for link in links:
        current = int(''.join(
            str(int(current & component != 0))
            for component in link
        ), 2)
        #print(bin(current)[2:].rjust(164, '0'))
    return current

def test_chain(links, start, end):
    current = start
    for link in links:
        current = int(''.join(
            str(int(current & component != 0))
            for component in link
        ), 2)
    return end == current & end

try:
    with open('hyperlink.json', 'r') as f:
        data = json.load(f)
except IOError:
    print('Could not open hyperlink.json')

alphabet = 'abcdefghijklmnopqrstuvwxyz{}_'
def branch(prefix):
    while len(prefix) < 34:
        counts = {}
        results = {}
        letters = []
        for char in alphabet:
            chain1 = prefix + char + '}'
            links = [data['links'][c] for c in chain1]
            res = bin(chain(links, data['start']))[2:].rjust(164, '0')
            results[char] = res
            if res not in counts:
                counts[res] = 1
            else:
                counts[res] += 1
        #print(counts)
        keys = [k for k, v in counts.items() if v == 1]
        try:
            letter = [k for k, v in results.items() if v == keys[0]]
            prefix += letter[0]
        except IndexError:
            prefix += '_'
    print(prefix + '}')

prefix = 'flag'
branch(prefix)
prefix = 'alg'
branch(prefix)
prefix = 'dice{'
branch(prefix) 
