#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes

c = 28361548396052470805609182453578811296488064111927275091465746476913023481206572454093064113389207519785161200961426105580316368625269715000880847694207735018858472578327415301675140848904695196197416945226625424889008830734957626121902545076351519606299300324512446125784810089682943237280874040201510272479
n = 34324010910101370405032828342262192285560653918790417913883664249459443563214253251280358509933785641445643754340765454837039485364522507628461319355281493786665758401920085329566342675578405334501254462249097312016832870306009221660768717370605131175122327715605174245203892512121128761348915583787535614609

# q = q_high * 2^448 + (n % 2^448)
# We know q_high is roughly 64 bits (512 - 448)

nbits = 448
r = n % (2^nbits)

# f = x * 2^nbits + r
# We need it monic: f = x + r * inverse(2^nbits, n)
inv_2_nbits = inverse_mod(2^nbits, n)
P.<x> = PolynomialRing(Zmod(n))
f = x + r * inv_2_nbits

# Howland's algorithm or Coppersmith's for finding a factor
# small_roots(X, beta) finds x0 such that f(x0) | n and f(x0) >= n^beta
# Here q approx sqrt(n), so beta = 0.5
# X is the bound for x, which is 2^(512-448) = 2^64

beta = 0.45 # q is around n^0.5, so 0.45 is safe
X = 2^(512 - nbits + 1)

roots = f.small_roots(X=X, beta=beta)

if roots:
    q_high = roots[0]
    q = int(q_high * 2^nbits + r)
    assert n % q == 0
    p = n // q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(long_to_bytes(int(m)).decode())
else:
    print("No roots found")
