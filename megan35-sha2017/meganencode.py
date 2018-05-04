import base64

megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
atom128 = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC"
zong22 = "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2"
hazz15 = "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5"
base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

class B64VariantEncoder:

    def __init__(self, translation):
        base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        self.lookup = dict(zip(base, translation))
        self.revlookup = dict(zip(translation, base))

    def encode(self, text):
        global lookup
        b64 = base64.b64encode(text)
        result = "".join([self.lookup[x] for x in b64])
        return result

    def decode(self, code):
        global revlookup
        b64 = "".join([self.revlookup[x] for x in code])
        result = base64.b64decode(b64)
        return result

def encode(text):
    encoder = B64VariantEncoder(megan35)
    return encoder.encode(text)

def decode(variant, code):
    try:
        encoder = B64VariantEncoder(variant)
        return encoder.decode(code)
    except KeyError:
        return "no valid encoding"
    except TypeError:
        return "no correct padding"

text = "\x0c\xa0\x04\x08"+"--%s"
text = "/bin/sh\x00"

print ("megan35:"+encode(text))
