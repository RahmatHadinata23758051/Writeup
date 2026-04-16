ciphertext = """Azza wfahv ztu. N rnvy, bndfah na zbfaztv vztak, n vztak ndfa uz n dcnqza zw n uzlvfa, icfuv nmztu. Nthtvutv, rgz gnv gnk n mnk afhgu, vfuv ty mcfadfah nak ytwmcfak. Zg rgnu rnv ugnu rzwk (fv gfv ugzthgu) ugnu wna ugwzthg bp mwnfa ncc afhgu, ugnu fkfzufl rzwk ugnu, gnwk nv F'k uwp uz yta fu kzra, rnv ncrnpv etvu na falg zw urz ztu zi bp hwnvy - izrc zw iztc zw Szr zw Szpnc? - n rzwk rgflg, mp nvvzlfnufza, mwzthgu fauz ycnp na falzahwtztv bnvv nak bnhbn zi aztav, fkfzbv, vczhnav nak vnpfahv, n lzaitvfah, nbzwygztv ztuyztwfah rgflg F vzthgu fa snfa uz lzauwzc zw utwa zii mtu rgflg rztak nwztak bp bfak n rgfwcrfak zi n lzwk, n rgfycnvg zi n lzwk, n lzwk ugnu rztck vycfu nhnfa nak nhnfa, rztck dafu nhnfa nak nhnfa, zi rzwkv rfugztu lzbbtaflnufza zw nap yzvvfmfcfup zi lzbmfanufza, rzwkv rfugztu ywzatalfnufza, vfhafiflnufza zw uwnavlwfyufza mtu ztu zi rgflg, azurfugvunakfah, rnv mwzthgu izwug n ictq, n lzaufatztv, lzbynlu nak ctlfk iczr: na fautfufza, n snlfccnufah iwfvvza zi fcctbfanufza nv fi lnthgu fa n icnvg zi cfhguafah zw fa n bfvu nmwtyucp wfvfah uz tavgwztk na zmsfztv vfha - mtu n vfha, ncnv, ugnu rztck cnvu na favunau zacp uz snafvg izw hzzk."""

# mapping hasil cryptanalysis monoalphabetic substitution
enc_to_dec = {
    'a':'n', 'b':'m', 'c':'l', 'd':'k', 'f':'i', 'g':'h', 'h':'g',
    'i':'f', 'k':'d', 'l':'c', 'm':'b', 'n':'a', 'q':'x', 'r':'w',
    's':'v', 't':'u', 'u':'t', 'v':'r', 'w':'p', 'y':'y', 'z':'o',
    'A':'N', 'F':'I', 'N':'A', 'S':'V', 'Z':'O'
}

def decode(text, mp):
    out = []
    for ch in text:
        if ch.isalpha():
            out.append(mp.get(ch, '?'))
        else:
            out.append(ch)
    return ''.join(out)

plain = decode(ciphertext, enc_to_dec)
print(plain)
