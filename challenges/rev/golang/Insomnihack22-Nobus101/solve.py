#
# This script must be run in Sage
#

import numpy as np
import os

# create 2**5 workers 
worker_id = 0
for i in range(5):
    worker_id = (worker_id << 1) | (0 if os.fork() else 1)

if worker_id:
    # known curve params 
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    E = EllipticCurve(GF(p), [-3, b])
    G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

    # reversed params 
    Q = E(0xe4443e00380471a612d205fc270dd16dff008f4adc4f2ad2c32fed8e74f76033, 0x07275f38738e8496bc0ade55de646372df388f04cdf6a09cf80108e0d2878ce5)
    x = 8665335155262475126035024804615308627879162522662682027290922872901918572096

    # create the mod
    n = E.order()
    Zn = Zmod(n)
    xi = Integer(1/Zn(x))
    
    # the numbers given by the server
    v1 = 0x920324424eed2d0575b12b12857d9684ac3486b5087cddf8a60e4e129939
    v2 = 0xce9c8866c6e5f6a0816d7c10dca0c2e6ffaa3101ccc882b371136766052
    print(f"running", worker_id)
    
    # optimized with np
    arrs = np.array_split(list(range(2**16)), 32)
    for dr in arrs[worker_id]:
        _r1 = v1 + 2**240 * dr
        try:
            R1 = E.lift_x(_r1)
            S1 = xi * R1
            _s2 = Integer(S1.xy()[0])
            _r2 = Integer((_s2 * Q).xy()[0])
            _v2 = _r2 & ((1<<240) - 1)

            if v2 != _v2: continue
            _s3 = Integer((_s2 * G).xy()[0])
            _r3 = Integer((_s3 * Q).xy()[0])
            _v3 = _r3 & ((1<<240) - 1)

            print(f'Got it!',hex(_v3))
            break
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as e:
            pass

    os.kill(os.getpid(), 9)
