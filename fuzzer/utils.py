import string
import struct
import subprocess
import os

def de_bruijn(alphabet, n):
    """Generates a De Bruijn sequence for alphabet and subsequences of length n."""
    k = len(alphabet)
    a = [0] * k * n
    sequence = []
    
    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    
    db(1, 1)
    return "".join(alphabet[i] for i in sequence)

def cyclic_pattern(length):
    """Generates a cyclic pattern of given length (Metasploit style)."""
    # Standard Metasploit pattern uses: Upper + Lower + Digit (3 chars = byte)
    # Actually, simpler cyclic usually is 4 bytes unique (x64) or 4 bytes unique (x32).
    # Common implementation: Aa0Aa1Aa2...
    
    charset_upper = string.ascii_uppercase
    charset_lower = string.ascii_lowercase
    charset_digit = string.digits
    
    pattern = []
    for u in charset_upper:
        for l in charset_lower:
            for d in charset_digit:
                pattern.append(u + l + d)
                if len(pattern) * 3 >= length:
                    return "".join(pattern)[:length]
    return "".join(pattern)[:length]

def cyclic_find(value_hex, length=None):
    """Finds the offset of value_hex in the pattern."""
    # Convert hex string (e.g., 0x41414141) to bytes/string
    try:
        if value_hex.startswith("0x"):
            value_hex = value_hex[2:]
        
        # Determine bit width by length
        byte_len = len(value_hex) // 2
        value_bytes = bytes.fromhex(value_hex)
        
        # Endianness: x86/x64 are little endian. TRACER returns hex.
        # But 'value_hex' from tracer is the integer value in register.
        # So 0x41414161 (latin 'aAAA') in register on LE machine
        # means memory was 'aAAA' (0x61, 0x41, 0x41, 0x41).
        # We need to reverse it to match string pattern.
        value_bytes_le = value_bytes[::-1]
        pattern_search_term = value_bytes_le.decode('latin-1')
        
        # Generate a large enough pattern
        pat = cyclic_pattern(length if length else 20000)
        
        offset = pat.find(pattern_search_term)
        return offset
    except Exception as e:
        return -1

def check_aslr():
    try:
        with open("/proc/sys/kernel/randomize_va_space", "r") as f:
            val = f.read().strip()
            if val == "0": return "OFF (0)"
            elif val == "1": return "Conservative (1)"
            elif val == "2": return "Full (2)"
            else: return f"Unknown ({val})"
    except:
        return "Unknown"

def check_pie(binary_path):
    # Rough check using `file` command if pyelftools not present
    try:
        out = subprocess.check_output(["file", binary_path]).decode()
        if "shared object" in out:
            return "PIE Enabled"
        elif "executable" in out:
            return "No PIE"
        else:
            return "Unknown"
    except:
        return "Unknown"
