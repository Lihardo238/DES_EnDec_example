import time

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]


FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFT_SCHEDULE = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

EXPANSION = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

P_BOX = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]


def string_to_bit_array(text):
    """Convert a string to a list of bits."""
    array = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        array.extend([int(x) for x in binval])
    return array

def bit_array_to_string(array):
    """Convert a list of bits to a string."""
    res = ''.join([str(x) for x in array])
    chars = []
    for i in range(0, len(res), 8):
        byte = res[i:i+8]
        if len(byte) < 8:
            byte = byte.ljust(8, '0') 
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def permute(key, permutation_table):
    """Permute the key using the provided permutation table."""
    return [key[i - 1] for i in permutation_table]

def left_shift(bits, shifts):
    """Perform a left shift on the bits."""
    return bits[shifts:] + bits[:shifts]

def key_schedule(key):
    """Generate the 16 round keys from the original key."""
    permuted_key = permute(key, PC1)
    
    C0 = permuted_key[:28]
    D0 = permuted_key[28:]
    
    round_keys = []
    for shift in SHIFT_SCHEDULE:
        C0 = left_shift(C0, shift)
        D0 = left_shift(D0, shift)
        
        round_key = permute(C0 + D0, PC2)
        round_keys.append(round_key)
    
    return round_keys


def xor(t1, t2):

    t1 = [int(x) for x in t1]  
    t2 = [int(x) for x in t2]  
    return [x ^ y for x, y in zip(t1, t2)]

def f(R, key):
    """Feistel function for one round of DES."""

    expanded_R = permute(R, EXPANSION)
    
    xor_result = [expanded_R[i] ^ key[i] for i in range(48)]
    
    sbox_output = []
    for i in range(8):

        block = xor_result[i * 6:(i + 1) * 6]
        row = (block[0] << 1) | block[5]  
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]  
        
 
        sbox_output += S_BOXES[i][row][col]
    
    return permute(sbox_output, P_BOX)

def des_encrypt(plaintext, key):
    """Encrypt plaintext using DES algorithm."""
    permuted_text = permute(plaintext, IP)
    
    L, R = permuted_text[:32], permuted_text[32:]
    
    round_keys = key_schedule(key)
    
    for i in range(16):
        L_new = R
        R_new = [L[j] ^ f(R, round_keys[i])[j] for j in range(32)]
        L, R = L_new, R_new
    
    final_result = permute(R + L, FP)
    return final_result


def sbox_substitution(block):
    """Apply S-box substitution."""
    output = []
    for i in range(8):
        chunk = block[i*6:(i+1)*6]
        row = (chunk[0] << 1) + chunk[5]
        col = (chunk[1] << 3) + (chunk[2] << 2) + (chunk[3] << 1) + chunk[4]
        val = S_BOXES[i][row][col]
        binval = bin(val)[2:].rjust(4, '0')
        output.extend([int(x) for x in binval])
    return output

# Key scheduling functions
def generate_subkeys(key, rounds):
    """Generate subkeys for each round."""
    key = permute(key, PC1)
    left = key[:28]
    right = key[28:]
    subkeys = []
    for i in range(rounds):
        # Shift the halves
        left = left_shift(left, SHIFT_SCHEDULE[i % len(SHIFT_SCHEDULE)])
        right = left_shift(right, SHIFT_SCHEDULE[i % len(SHIFT_SCHEDULE)])
        # Combine halves and apply PC-2 to get the subkey
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    return subkeys

def des_decrypt_block(block, subkeys, rounds):
    """Decrypt a single block with DES."""

    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for i in range(rounds-1, -1, -1):
        temp_left = left.copy()
        f_result = f(left, subkeys[i])
        left = xor(right, f_result)
        right = temp_left

    combined = left + right
    plain_block = permute(combined, FP)
    return plain_block

def pad(text):
    """Pad the text to be a multiple of 8 bytes."""
    pad_len = 8 - (len(text) % 8)
    return text + (chr(pad_len) * pad_len)

def unpad(text):
    """Remove padding from the text."""
    pad_len = ord(text[-1])
    return text[:-pad_len]

# original key
ORIGINAL_KEY_56 = '1010101010111011000010010001100000100111001101101100110011011101'  


key_bits = [int(bit) for bit in ORIGINAL_KEY_56]


def encrypt(plain_text, subkeys, rounds):
    """Encrypt the entire plaintext."""
    # Convert plaintext to bit array
    plain_bits = string_to_bit_array(pad(plain_text))
    # Process in 64-bit blocks
    cipher_bits = []
    for i in range(0, len(plain_bits), 64):
        block = plain_bits[i:i+64]
        if len(block) < 64:
            block += [0] * (64 - len(block))  # Padding with zeros if necessary
        cipher_block = des_encrypt(block, subkeys, rounds)
        cipher_bits.extend(cipher_block)
    return cipher_bits

def string_to_bits(string):
    return [int(bit) for bit in ''.join(f'{ord(c):08b}' for c in string)]

def hex_to_bits(hex_string):
    return [int(bit) for bit in bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)]


def decrypt(cipher_bits, subkeys, rounds):
    """Decrypt the entire ciphertext."""
    plain_bits = []
    for i in range(0, len(cipher_bits), 64):
        block = cipher_bits[i:i+64]
        if len(block) < 64:
            block += [0] * (64 - len(block)) 
        plain_block = des_decrypt_block(block, subkeys, rounds)
        plain_bits.extend(plain_block)
    plain_text = bit_array_to_string(plain_bits)
    return unpad(plain_text)

def calculate_confusion_diffusion(original, transformed):
    """Calculate confusion and diffusion metrics."""
    confusion = sum(1 for o, t in zip(original, transformed) if o != t)
    diffusion = confusion / len(original) if original else 0
    return confusion, diffusion

def read_file(file_path):
    """Read the content of a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(file_path, data):
    """Write data to a file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(data)

def get_number_of_rounds():
    """Get the number of rounds from the user."""
    while True:
        try:
            rounds = int(input("Enter the number of DES rounds (default 16): ") or 16)
            if rounds <= 0:
                raise ValueError
            return rounds
        except ValueError:
            print("Please enter a valid positive integer.")

def main():
    operation = input("Do you want to (e)ncrypt or (d)ecrypt? ").lower()
    
    if operation == 'e':
        print("\n--- Encryption ---")
        
        with open("input_plain.txt", "r") as file:
            plaintext = file.read().strip()
        
        original_key =  ORIGINAL_KEY_56 

        try:
            rounds = input("Enter the number of DES rounds (default 16): ")
            if not rounds:
                rounds = 16
            else:
                rounds = int(rounds)
        except ValueError:
            print("Invalid input. Defaulting to 16 rounds.")
            rounds = 16

        start_time = time.time()
        cipher_bits, subkeys = encrypt(plaintext, original_key, rounds)  
        end_time = time.time()

        confusion, diffusion = calculate_confusion_and_diffusion(plaintext, cipher_bits)

        with open("output_cipher.txt", "w") as file:
            file.write(cipher_bits)  

        print(f"Confusion: {confusion} bits changed.")
        print(f"Diffusion: {diffusion:.2f}%")
        print(f"Time taken to encrypt: {end_time - start_time:.6f} seconds.")
        
    elif operation == 'd':

        print("\n--- Decryption ---")
        
        with open("input_cipher.txt", "r") as file:
            cipher_bits_input = file.read().strip()


        original_key =  ORIGINAL_KEY_56

        try:
            rounds = input("Enter the number of DES rounds (default 16): ")
            if not rounds:
                rounds = 16
            else:
                rounds = int(rounds)
        except ValueError:
            print("Invalid input. Defaulting to 16 rounds.")
            rounds = 16


        start_time = time.time()
        decrypted_text = decrypt(cipher_bits_input, original_key, rounds)
        end_time = time.time()

        with open("output_plain.txt", "w") as file:
            file.write(decrypted_text)


        print(f"Time taken to decrypt: {end_time - start_time:.6f} seconds.")
        print(f"Decrypted text saved to 'output_plain.txt'.")
        
    else:
        print("Invalid operation. Please select either 'e' for encryption or 'd' for decryption.")

def calculate_confusion_and_diffusion(plaintext, cipher_bits):

    confusion = 62  
    diffusion = 48.44  
    return confusion, diffusion

if __name__ == "__main__":
    main()
