#!/usr/bin/env python3

MOD = 10**9 + 7
INITIAL_VALUES = (1337, 2137, 999)
NUMBER_OF_MINERALS = 13

FLAG1_DATA = [
    (13691526, 85),
    (67714635, 250),
    (45889193, 92),
    (119333921, 92),
    (28660401, 71),
    (91192320, 226),
    (98698869, 14),
]

FLAG2_DATA = [
    (19385771243582136162726, 119),
    (20338468563599170406034, 244),
    (20348006767133331653585, 84),
    (20855346972076738813432, 108),
    (21275032782538569035493, 44),
    (21688316937478910332906, 213),
    (10000000000000000000000, 248),
    (10434543483380626658076, 213),
    (11432360796540021360875, 89),
    (11893508966092798746611, 0),
    (12629823227009614311307, 71),
    (13239336466487376418254, 130),
    (14213837926783723743645, 144),
    (15144837827511220276057, 129),
    (15901977772834060831411, 234),
    (16759029998774462742839, 143),
    (17454032695551734274782, 170),
    (18154830948193389431256, 102),
    (18647374405210769869223, 151),
]

A = (
    (3, 2, 5),
    (1, 4, 0),
    (0, 1, 2),
)


def mat_mul(x, y):
    return tuple(
        tuple(
            (x[i][0] * y[0][j] + x[i][1] * y[1][j] + x[i][2] * y[2][j]) % MOD
            for j in range(3)
        )
        for i in range(3)
    )


def mat_pow(n):
    r = (
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
    )
    b = A
    while n > 0:
        if n & 1:
            r = mat_mul(r, b)
        b = mat_mul(b, b)
        n >>= 1
    return r


def sss_fast(ts):
    m = mat_pow(ts)
    return (
        m[0][0] * INITIAL_VALUES[0]
        + m[0][1] * INITIAL_VALUES[1]
        + m[0][2] * INITIAL_VALUES[2]
    ) % MOD


def decode_flag(flag_data, new_pickaxe=False):
    chars = []
    for ts, encrypted_value in flag_data:
        key_byte = sss_fast(ts) & 0xFF
        chars.append(chr(encrypted_value ^ key_byte))

    if new_pickaxe and chars:
        chars = chars[-NUMBER_OF_MINERALS:] + chars[:-NUMBER_OF_MINERALS]

    return "".join(chars)


def main():
    f1 = decode_flag(FLAG1_DATA, new_pickaxe=False)
    f2 = decode_flag(FLAG2_DATA, new_pickaxe=True)
    flag = f1 + f2
    print(flag)


if __name__ == "__main__":
    main()
