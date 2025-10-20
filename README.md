Tool developed while practicing for Fall '25 National Cyber League. Recursive, order-independent decoder. 
Tracks full decoding path. Ranks outputs by confidence (English likelihood). 
Checks: Caesar, ROT47, @bash, vignere, rail, bases.
Takes cyphertext as string input, quotes needed. --vkey can be entered when Vignere key is known.
--RSA flag takes user from cypertext, to prompts for solving RSA problems when knowing n (modulus) and e (public) exponent

To do:
  More thorough testing.
  Manual page.
