import re
from urllib.parse import urlparse

def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc  
    path = parsed.path
    full = url

    # Fix: strip port if present before IP check
    hostname = domain.split(':')[0]

    def count_char(s, ch): return s.count(ch)

    no_letters = sum(c.isalpha() for c in full)
    no_digits = sum(c.isdigit() for c in full)
    special_chars = re.findall(r'[^a-zA-Z0-9]', full)
    obfuscated = re.findall(r'%[0-9a-fA-F]{2}', full)
    subdomains = domain.split('.')[:-2] if domain else []

    return {
        'URLLength':                    len(full),
        'DomainLength':                 len(domain),
        'IsDomainIP':                   1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0,
        'TLDLegitimateProb':            _tld_prob(parsed),
        'URLCharProb':                  no_letters / len(full) if full else 0,
        'NoOfSubDomain':                len(subdomains),
        'HasObfuscation':               1 if obfuscated else 0,
        'NoOfObfuscatedChar':           len(obfuscated),
        'NoOfLettersInURL':             no_letters,
        'LetterRatioInURL':             no_letters / len(full) if full else 0,
        'NoOfDegitsInURL':              no_digits,
        'DegitRatioInURL':              no_digits / len(full) if full else 0,
        'NoOfEqualsInURL':              count_char(full, '='),
        'NoOfQMarkInURL':               count_char(full, '?'),
        'NoOfAmpersandInURL':           count_char(full, '&'),
        'NoOfOtherSpecialCharsInURL':   len(special_chars),
        'SpacialCharRatioInURL':        len(special_chars) / len(full) if full else 0,
        'IsHTTPS':                      1 if parsed.scheme == 'https' else 0,
        'CharContinuationRate':         _char_continuation(full),
    }
def _tld_prob(parsed) -> float:
    COMMON_TLDS = {
        'com': 0.52, 'org': 0.08, 'net': 0.07, 'edu': 0.03,
        'gov': 0.02, 'uk': 0.03,  'de': 0.03,  'in': 0.02,
        'io':  0.01, 'co': 0.02
    }
    parts = parsed.netloc.split('.')
    tld = parts[-1] if parts else ''
    return COMMON_TLDS.get(tld.lower(), 0.005)

def _char_continuation(url: str) -> float:
    if not url:
        return 0.0
    max_run = run = 1
    for i in range(1, len(url)):
        if url[i].isalpha() and url[i-1].isalpha():
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run / len(url)