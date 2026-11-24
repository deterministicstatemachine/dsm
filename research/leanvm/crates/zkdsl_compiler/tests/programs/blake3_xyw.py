# BLAKE3 compressions through the `BLAKE3` instruction (research build): the one-block hash of
# the bytes 0..64, then a compression of its digest and the message's second half with X, Y and W
# placed at the 25-byte offset (counter 5, flags CHUNK_START), then a chained one with a counter
# past 2^32, a short block and CHUNK_END | ROOT. Published: the last chaining value's two cells.
# public_input: 277043669924330974795999708547963775634, 207052337065397815011494928395067158638
from snark_lib import *


def main():
    a = StackBuf(2)
    b = StackBuf(2)
    iv = StackBuf(2)
    h1 = StackBuf(2)
    h2 = StackBuf(2)
    h3 = StackBuf(2)
    x = StackBuf(2)
    y = StackBuf(2)
    w = StackBuf(2)
    a[0] = 20011376718272490338853433276725592320
    a[1] = 41362427191743139026751447860679676176
    b[0] = 62713477665213787714649462444633760032
    b[1] = 84064528138684436402547477028587843888
    iv[0] = 219737784560624922979293950613486429799
    iv[1] = 122126981997165389778004304960695456383
    x[0] = 141414077682499347914967658848576276481
    x[1] = 290871430996793888730253760936254863473
    y[0] = 224128465864773140356368643778472906243
    y[1] = 117373213497419896916950911031540563635
    w[0] = 266820100610501952120062762154918351365
    w[1] = 202766949190090006056368718407367910101
    blake3(a, b, iv, 871509788837499334246394757120, h1)
    blake3(h1, b, iv, 79228163694855958310955253765, h2, x=x, y=y, w=w)
    blake3(h2, h1, h2, 792281625751385931467366334467, h3)
    p = GEN ** 0
    p[1] = h3[0]
    p[GEN] = h3[1]
    return
