
#!/usr/bin/env python3
"""
CTF Universal Cipher Solver v3
------------------------------
- Recursive, order-independent decoder
- Tracks full decoding path
- Ranks outputs by confidence (English likelihood)
"""

import base64, urllib.parse, string, gzip, zlib, re
from itertools import product
from math import log10

# ---------- English scoring ----------
QUAD = {"TION":0.001,"THER":0.001,"HERE":0.0008,"OULD":0.0006,
        "THAT":0.0006,"WITH":0.0005,"ING ":0.0005,"AND ":0.0004}

def quad_score(txt):
    t = ''.join(ch for ch in txt.upper() if ch.isalpha() or ch==' ')
    return sum(log10(QUAD.get(t[i:i+4],1e-7)) for i in range(max(0,len(t)-3)))

def looks_english(s):
    s = s.lower()
    return (" " in s) and any(w in s for w in ["flag","ctf"," the "," and "," is ","safe","key","cipher","used"])

def confidence_score(text):
    score = quad_score(text)
    if looks_english(text): score += 2.0
    if "flag{" in text.lower() or "ctf{" in text.lower(): score += 5.0
    printable = sum(c.isprintable() for c in text)/max(len(text),1)
    score += printable
    return score

# ---------- Classical ----------
def caesar(s,shift):
    out=[]
    for c in s:
        if c.isalpha():
            b=ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c)-b+shift)%26+b))
        else: out.append(c)
    return ''.join(out)

def rot47(s):
    return ''.join(chr(33+((ord(c)+14)%94)) if 33<=ord(c)<=126 else c for c in s)

ATBASH_TABLE=str.maketrans(
    string.ascii_lowercase+string.ascii_uppercase,
    string.ascii_lowercase[::-1]+string.ascii_uppercase[::-1])
def atbash(s): return s.translate(ATBASH_TABLE)

def vigenere_decrypt(ct,key):
    r,ki=[],0
    for c in ct:
        if c.isalpha():
            b=ord('A') if c.isupper() else ord('a')
            k=ord(key[ki%len(key)].lower())-97
            r.append(chr((ord(c)-b-k)%26+b))
            ki+=1
        else: r.append(c)
    return ''.join(r)

# ---------- Rail Fence ----------
def rail_decrypt(ct,key):
    ct=re.sub(r"\s+","",ct)
    rail_len=[0]*key
    pat=list(range(key))+list(range(key-2,0,-1))
    seq=[pat[i%len(pat)] for i in range(len(ct))]
    for i in seq: rail_len[i]+=1
    rails,idx,pos=[],0,[0]*key
    for rl in rail_len:
        rails.append(list(ct[idx:idx+rl])); idx+=rl
    res=[]
    for i in seq:
        res.append(rails[i][pos[i]]); pos[i]+=1
    return ''.join(res)

def auto_rail(ct):
    outs=[]
    for k in range(2,9):
        pt=rail_decrypt(ct,k)
        outs.append((k,pt,confidence_score(pt)))
    return sorted(outs,key=lambda x:x[2],reverse=True)[:2]

# ---------- Encodings ----------
def try_base(txt):
    outs=[]
    for n,f in [("B64",base64.b64decode),("B32",lambda s:base64.b32decode(s,casefold=True)),("B85",base64.b85decode)]:
        try: outs.append((n,f(txt.encode()).decode()))
        except: pass
    return outs

def try_hex(txt):
    c=re.sub(r"[^0-9A-Fa-f]","",txt)
    if len(c)%2==0:
        try: return [("Hex",bytes.fromhex(c).decode())]
        except: return []
    return []

def try_url(txt):
    if "%" in txt or "+" in txt:
        try: return [("URL",urllib.parse.unquote(txt))]
        except: pass
    return []

# ---------- Hash check ----------
def detect_hash(t):
    clean=re.sub(r"[^0-9a-fA-F]","",t)
    lens={32:"MD5",40:"SHA1",56:"SHA224",64:"SHA256",96:"SHA384",128:"SHA512"}
    if len(clean) in lens: print(f"[!] Looks like {lens[len(clean)]} hash.")

# ---------- Recursive engine ----------
def recursive_decode(txt, depth=1, path=None, max_depth=6):
    if path is None: path=[]
    if depth>max_depth: return []

    results=[]

    # Atbash
    at=atbash(txt)
    if looks_english(at):
        results.append(("Atbash",at,path+["Atbash"],confidence_score(at)))

    # Caesar small shifts
    for s in range(1,6):
        c=caesar(txt,s)
        if looks_english(c):
            results.append((f"Caesar({s})",c,path+[f"Caesar({s})"],confidence_score(c)))

    # ROT47
    r47=rot47(txt)
    if looks_english(r47):
        results.append(("ROT47",r47,path+["ROT47"],confidence_score(r47)))

    # Vigenère brute small keys
    alpha=string.ascii_lowercase
    for L in range(1,3):
        for k in product(alpha,repeat=L):
            key=''.join(k)
            pt=vigenere_decrypt(txt,key)
            if looks_english(pt):
                results.append((f"Vigenere[{key}]",pt,path+[f"Vigenere[{key}]"],confidence_score(pt)))

    # Base/Hex/URL
    for name,out in try_base(txt)+try_hex(txt)+try_url(txt):
        results.append((name,out,path+[name],confidence_score(out)))

    # Rail Fence
    for k,pt,sc in auto_rail(txt):
        if looks_english(pt):
            results.append((f"RailFence({k})",pt,path+[f"RailFence({k})"],sc))

    # Recursive step
    all_results=[]
    for name,out,new_path,sc in results:
        all_results.append((name,out,new_path,sc))
        for deeper in recursive_decode(out,depth+1,new_path,max_depth):
            all_results.append(deeper)
    return all_results

# ---------- Main ----------
if __name__=="__main__":
    print("=== CTF Universal Cipher Solver v3 (path tracking + confidence) ===")
    c=input("Enter ciphertext: ").strip()
    sols=recursive_decode(c)
    if not sols:
        print("No clear plaintexts found.")
    else:
        sols.sort(key=lambda x:x[3],reverse=True)
        print("\n=== Ranked Candidates ===")
        for i,(name,out,path,score) in enumerate(sols[:10],1):
            print(f"[#{i} | Confidence {score:.2f}]")
            print("Path:", " → ".join(path))
            print("Plaintext:", out)
            print("-"*70)
