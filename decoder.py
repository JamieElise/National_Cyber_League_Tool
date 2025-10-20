#!/usr/bin/env python3
"""
CTF Universal Cipher Solver v3.1
- Recursive, order-independent decoder
- Tracks full decoding path
- Ranks outputs by confidence (English likelihood)
- NEW: --vkey KEY (one or many) to try Vigenère with explicit keys
- NEW: --RSA KEY take you into RSA tool
"""

import argparse, base64, urllib.parse, string, re
from itertools import product
from math import log10

# ---------- English scoring ----------
QUAD = {"TION":0.001,"THER":0.001,"HERE":0.0008,"OULD":0.0006,
        "THAT":0.0006,"WITH":0.0005,"ING ":0.0005,"AND ":0.0004}

def quad_score(txt):
    t = ''.join(ch for ch in txt.upper() if ch.isalpha() or ch==' ')
    if len(t) < 4:
        return -1e6
    return sum(log10(QUAD.get(t[i:i+4],1e-7)) for i in range(len(t)-3))

def looks_english(s):
    sl = s.lower()
    return (" " in sl) and any(w in sl for w in ["flag","ctf"," the "," and "," is ","safe","key","cipher","used","fear","lack"])

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
    txt = re.sub(r"\s+","",ct)
    if key <= 1 or key >= len(txt): return txt
    pattern = list(range(key)) + list(range(key-2,0,-1))
    seq = [pattern[i % len(pattern)] for i in range(len(txt))]
    rail_len = [0]*key
    for i in seq: rail_len[i]+=1
    rails, idx = [], 0
    for rl in rail_len:
        rails.append(list(txt[idx:idx+rl])); idx += rl
    pos = [0]*key
    out=[]
    for i in seq:
        out.append(rails[i][pos[i]]); pos[i]+=1
    return ''.join(out)

def auto_rail(ct, kmin=2, kmax=9, top=2):
    outs=[]
    for k in range(kmin, kmax+1):
        pt=rail_decrypt(ct,k)
        outs.append((k,pt,confidence_score(pt)))
    return sorted(outs,key=lambda x:x[2],reverse=True)[:top]

# ---------- Encodings ----------
def try_base(txt):
    outs=[]
    for n,f in [("B64",base64.b64decode),("B32",lambda s:base64.b32decode(s,casefold=True)),("B85",base64.b85decode)]:
        try:
            outs.append((n,f(txt.encode()).decode(errors="strict")))
        except Exception:
            pass
    return outs

def try_hex(txt):
    c=re.sub(r"[^0-9A-Fa-f]","",txt)
    if len(c)%2==0 and c:
        try: return [("Hex",bytes.fromhex(c).decode(errors="strict"))]
        except Exception: return []
    return []

def try_url(txt):
    if "%" in txt or "+" in txt:
        try: return [("URL",urllib.parse.unquote(txt))]
        except Exception: pass
    return []

# ---------- Hash check ----------
def detect_hash(t):
    clean=re.sub(r"[^0-9a-fA-F]","",t)
    lens={32:"MD5",40:"SHA1",56:"SHA224",64:"SHA256",96:"SHA384",128:"SHA512"}
    if len(clean) in lens: print(f"[!] Looks like {lens[len(clean)]} hash (one-way).")

# ---------- Recursive engine ----------
def recursive_decode(txt, forced_vkeys=None, depth=1, path=None, max_depth=6):
    if path is None: path=[]
    if forced_vkeys is None: forced_vkeys=[]
    if depth>max_depth: return []

    results=[]

    # Atbash
    at=atbash(txt)
    results.append(("Atbash", at, path+["Atbash"], confidence_score(at)))

    # Caesar (1..5) + ROT47
    for s in range(1,6):
        c=caesar(txt,s)
        results.append((f"Caesar({s})", c, path+[f"Caesar({s})"], confidence_score(c)))
    r47=rot47(txt)
    results.append(("ROT47", r47, path+["ROT47"], confidence_score(r47)))

    # Vigenère: explicit keys first (user-supplied)
    for key in forced_vkeys:
        if not key or not key.isalpha(): continue
        pt = vigenere_decrypt(txt, key)
        results.append((f"Vigenere[{key}]", pt, path+[f"Vigenere[{key}]"], confidence_score(pt)))

    # Vigenère: small brute (1–2 letters) remain as a light heuristic
    alpha=string.ascii_lowercase
    for L in range(1,3):
        for k in product(alpha,repeat=L):
            key=''.join(k)
            pt=vigenere_decrypt(txt,key)
            results.append((f"Vigenere[{key}]", pt, path+[f"Vigenere[{key}]"], confidence_score(pt)))

    # Encodings
    for name,out in try_base(txt)+try_hex(txt)+try_url(txt):
        results.append((name,out,path+[name],confidence_score(out)))

    # Rail Fence (top candidates)
    for k,pt,sc in auto_rail(txt):
        results.append((f"RailFence({k})", pt, path+[f"RailFence({k})"], sc))

    # Deduplicate identical plaintexts but keep best score/path
    best_map={}
    for name,out,new_path,sc in results:
        k = (out,)
        if k not in best_map or sc > best_map[k][2]:
            best_map[k] = (name, new_path, sc)

    # Recurse deeper on promising candidates
    all_results=[]
    for (out,), (name, new_path, sc) in best_map.items():
        all_results.append((name, out, new_path, sc))
        # Only recurse if output looks somewhat promising to avoid explosion
        if sc > -10:  # loose cutoff
            for deeper in recursive_decode(out, forced_vkeys, depth+1, new_path, max_depth):
                all_results.append(deeper)

    return all_results

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="CTF Universal Cipher Solver v3.1")
    p.add_argument("ciphertext", nargs="?", help="Ciphertext to decode (if omitted, you will be prompted).")
    p.add_argument("--vkey", action="append", default=[], help="Explicit Vigenère key to try (use multiple --vkey for several keys).")
    p.add_argument("--maxdepth", type=int, default=6, help="Max recursion depth (default 6).")
    p.add_argument("--RSA", "-RSA", action="store_true", help="Launch the RSA decryption helper.")
    return p.parse_args()

def main():
    import sys, os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import RSA_Tool
    args = parse_args()

    # --- RSA helper mode ---
    if args.RSA:
        print("=== RSA Decryption Helper ===")
        RSA_Tool.main()
        return

    # --- Normal solver mode ---
    c = args.ciphertext or input("Enter ciphertext: ").strip()

