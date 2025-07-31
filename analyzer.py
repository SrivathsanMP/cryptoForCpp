import re

def detect_encryption(code):
    code = code.lower()

    if 'cryptography.hazmat' in code or 'fernet' in code:
        return '🔐 Detected: Fernet (Symmetric - Cryptography Module)'
    elif 'aes' in code and ('from cryptography' in code or 'pycryptodome' in code):
        return '🔐 Detected: AES Encryption'
    elif 'rsa' in code and ('cryptography' in code or 'rsa.newkeys' in code):
        return '🔐 Detected: RSA Encryption'
    elif 'blowfish' in code:
        return '🔐 Detected: Blowfish Encryption'
    elif 'des' in code:
        return '🔐 Detected: DES Encryption'
    elif 'arc4' in code:
        return '🔐 Detected: ARC4 Stream Cipher'
    elif 'public_key' in code and 'private_key' in code:
        return '🔐 Detected: Public/Private Key Encryption'
    else:
        return '❌ No recognizable encryption method detected.'


def analyze_crypto_code(code):
    issues = []

    # ---------- 1. AES ECB MODE CHECK ----------
    if "AES" in code and "MODE_ECB" in code:
        issues.append({
            "type": "AES Mode",
            "problem": "ECB mode detected",
            "explanation": "ECB (Electronic Codebook) mode encrypts identical plaintext blocks into identical ciphertext blocks. This reveals patterns and is insecure for most data."
        })

    # ---------- 2. AES WEAK KEY LENGTH CHECK ----------
    key_matches = re.findall(r'key\s*=\s*b?[\'"](.*?)[\'"]', code)
    for key in key_matches:
        key_len = len(key.encode())
        if key_len < 16:
            issues.append({
                "type": "AES Key",
                "problem": f"Weak AES key detected (length = {key_len} bytes)",
                "explanation": f"The AES key is too short. AES-128 requires at least 16 bytes. Using a {key_len}-byte key makes encryption insecure."
            })

    # ---------- 3. CBC MODE IV PRESENCE CHECK ----------
    if "MODE_CBC" in code:
        has_iv = re.search(r'iv\s*=', code) or re.search(r'IV\s*=', code)
        if not has_iv:
            issues.append({
                "type": "CBC IV",
                "problem": "CBC mode used without IV",
                "explanation": "CBC (Cipher Block Chaining) mode must use an initialization vector (IV). Without an IV, the encryption is vulnerable to known-plaintext attacks."
            })

    return issues

# ----------- Test Code -------------
if __name__ == "__main__":
    sample_code = '''
from Crypto.Cipher import AES

key = b'12345'
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b'HelloWorld123456')

cipher2 = AES.new(key, AES.MODE_CBC)
    '''

    result = analyze_crypto_code(sample_code)

    if not result:
        print("✅ No obvious cryptographic issues found.")
    else:
        for idx, issue in enumerate(result, start=1):
            print(f"\n🚨 Issue {idx}: {issue['problem']}")
            print(f"🔍 Explanation: {issue['explanation']}")
