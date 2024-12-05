# -*- coding: utf-8 -*-
"""
Created on Mon Dec  2 21:32:38 2024

@author: Marie Françoise Cathy G.
"""

import hashlib
import tkinter as tk


# 1 - Hash values and array of round constants

# Hash values initialisation
"""
Hash values are constants expressed in hexadecimal and given in the specifications for the SHA-256 function. 
They represent the first 32 bits of the fractional parts of the square roots for each of the first 8 prime numbers. 
Example for the fist hash value:
    - prime number: 2
    - square root: 2^(1/2) ≈ 1.414213562
    - fractional part: 0.414213562
    - 32-bit hexadecimal conversion: 0.414213562 * (2^32) ≈ 1779033703 = 0x6a09e667
    => h0 = 0x6a09e667
    
"""

h0 = 0x6a09e667 
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

initial_H = [h0, h1, h2, h3, h4, h5, h6, h7]

# Array of round constants initialisation
    
"""
Round constants are constants expressed in hexadecimal and given in the specifications for the SHA-256 function. 
They represent the first 32 bits of the fractional parts of the cube roots for each of the first 64 prime numbers. 
Example for the fist round constant:
    - prime number: 2
    - square root: 2^(1/3) ≈ 1.259921049
    - fractional part: 0.259921049
    - 32-bit hexadecimal conversion: 0.259921049 * (2^32) ≈ 1116352408 = 0x428a2f98
    => k0 = 0x428a2f98
    
"""

k0 = 0x428a2f98
k1 = 0x71374491
k2 = 0xb5c0fbcf
k3 = 0xe9b5dba5
k4 = 0x3956c25b
k5 = 0x59f111f1
k6 = 0x923f82a4
k7 = 0xab1c5ed5
k8 = 0xd807aa98
k9 = 0x12835b01
k10 = 0x243185be
k11 = 0x550c7dc3
k12 = 0x72be5d74
k13 = 0x80deb1fe
k14 = 0x9bdc06a7
k15 = 0xc19bf174
k16 = 0xe49b69c1
k17 = 0xefbe4786
k18 = 0x0fc19dc6
k19 = 0x240ca1cc
k20 = 0x2de92c6f
k21 = 0x4a7484aa
k22 = 0x5cb0a9dc
k23 = 0x76f988da
k24 = 0x983e5152
k25 = 0xa831c66d
k26 = 0xb00327c8
k27 = 0xbf597fc7
k28 = 0xc6e00bf3
k29 = 0xd5a79147
k30 = 0x06ca6351
k31 = 0x14292967
k32 = 0x27b70a85
k33 = 0x2e1b2138
k34 = 0x4d2c6dfc
k35 = 0x53380d13
k36 = 0x650a7354
k37 = 0x766a0abb
k38 = 0x81c2c92e
k39 = 0x92722c85
k40 = 0xa2bfe8a1
k41 = 0xa81a664b
k42 = 0xc24b8b70
k43 = 0xc76c51a3
k44 = 0xd192e819
k45 = 0xd6990624
k46 = 0xf40e3585
k47 = 0x106aa070
k48 = 0x19a4c116
k49 = 0x1e376c08
k50 = 0x2748774c
k51 = 0x34b0bcb5
k52 = 0x391c0cb3
k53 = 0x4ed8aa4a
k54 = 0x5b9cca4f
k55 = 0x682e6ff3
k56 = 0x748f82ee
k57 = 0x78a5636f
k58 = 0x84c87814
k59 = 0x8cc70208
k60 = 0x90befffa
k61 = 0xa4506ceb
k62 = 0xbef9a3f7
k63 = 0xc67178f2


K = [
    k0, k1, k2, k3, k4, k5, k6, k7,
    k8, k9, k10, k11, k12, k13, k14, k15,
    k16, k17, k18, k19, k20, k21, k22, k23,
    k24, k25, k26, k27, k28, k29, k30, k31,
    k32, k33, k34, k35, k36, k37, k38, k39,
    k40, k41, k42, k43, k44, k45, k46, k47,
    k48, k49, k50, k51, k52, k53, k54, k55,
    k56, k57, k58, k59, k60, k61, k62, k63
]

# 2 - Pre-processing (Padding)

"""
To ensure the message length is a multiple of 512 bits, we add padding according to the following formula:
n x 512 = M + 1 + P + 64
where:
M is the original message's length
P is the number of padding bits
"+ 1" accounts for the "1" bit (b'\x80')
"+ 64" is the length field in bits

We calculate the required padding and then, we append the 64-bit length of the original message to the padded message.
"""

def preprocess(message):
    original_length = len(message) * 8  # The original message's length in bits (1 byte = 8 bits)
    binary_1_to_add = b'\x80'  # "1" bit followed by seven "0" bits
    binary_0_to_add = b'\x00'  # Byte of "0" bits
    
    # We compute the number of padding bytes required
    nbr_bits_to_add = (448 - (len(message) * 8 + 8) % 512) % 512 # We add 8 bits for the binary_1_to_add and ensure the total length equals to (512-64) bits.
    nbr_bytes_to_add = nbr_bits_to_add // 8  # Convertion of bits to bytes    
    padding = binary_1_to_add + binary_0_to_add * nbr_bytes_to_add
    message += padding  # We add the padding to the original message
    
    # We append the original length as a 64-bit big-endian integer
    message += original_length.to_bytes(8, byteorder='big')
    
    return message



# 3 - Compression function
"""
The whole message block, which is n x 512 bits long, will be divided into n chunks of 512 bits.
Each chunk will then be put through 64 rounds of operations, with the result being provided as input for the next round of operations.

During the first 16 rounds, we further break down the 512-bit message into 16 pieces, each consisting of 32 bits. 
Indeed, we must compute the value for W(i) at each step.

Compression function
W(i) = W(i-16) + sigma(0) + W(i-7) + sigma(1)
where:
sigma(0) = (ROTR⁷(W(i-15))) XOR (ROTR¹⁸(W(i-15))) XOR (SHR³(W(i-15)))
sigma(1) = (ROTR¹⁷(W(i-2))) XOR (ROTR¹⁹(W(i-2))) XOR (SHR¹⁰(W(i-2)))
ROTRⁿ(x) is the circular right rotation of x by n bits
SHRⁿ(x) is the circular right shift of x by n bits

Example of one loop of the compression function:
for i from 0 to 64:
    Sum1(e) = RotR(e, 6) XOR RotR(e, 11) XOR RotR(e, 25)
    ch(e, f, g) = (e & f) XOR (~e & g)
    temp1 = h + Sum1(e) + ch(e, f, g) + K[i] + w[i]
    Sum0(a) = RotR(a, 2) XOR RotR(a, 13) XOR RotR(a, 22)
    maj(a, b, c) = (a & b) XOR (a & c) XOR (b & c)
    temp2 = Sum0(a) + maj(a, b, c)

    # Update the variables
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

"""

def RotR(value, bits):
    """
    Operation to right rotate a 32-bit integer by a specific number of bits
    """
    return (value >> bits) | (value << (32 - bits)) & 0xFFFFFFFF

def ShR(value, bits):
    """
    Operation to right shift a 32-bit integer by a specific number of bits
    """
    return value >> bits

def  chunk_processing(chunk, H, K):    
    """
    This function aims to process a single 512-bit chunk during the SHA-256 hashing process.
    Three parameters are used:
    - chunk: A 512-bit block of the message
    - H: The current hash values (array of 8 32-bit integers)
    - K: An array of 64 32-bit round constants

    The function:
    1 - Expands the 512-bit chunk into an array of 64 words (32 bits each) for message scheduling
    2 - Iterates through 64 rounds of compression
    3 - Updates the hash values based on the computed results for this chunk
    """

    w = [0] * 64  # Initialisation of an array of 64 words

    for i in range(16):
        # Each chunk is 512 bits, so we get 4 bytes at a time for each 32-bit word
        byte_chunk = chunk[i*4 : i*4+4]
        w[i] = int.from_bytes(byte_chunk, byteorder='big')  # Convert 4 bytes to a 32-bit word
    
    # Extend the remaining 48 words of the schedule using the formula of SHA-256
    for i in range(16, 64):
        s0 = RotR(w[i-15], 7) ^ RotR(w[i-15], 18) ^ ShR(w[i-15], 3)
        s1 = RotR(w[i-2], 17) ^ RotR(w[i-2], 19) ^ ShR(w[i-2], 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF  # Ensure 32-bit result

    # Initialise working variables to current hash value
    a, b, c, d, e, f, g, h = H

    # Compression function main loop
    for i in range(64):
        S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        # We can now update the working variables
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # And then update the hash values
    H[0] = (H[0] + a) & 0xFFFFFFFF
    H[1] = (H[1] + b) & 0xFFFFFFFF
    H[2] = (H[2] + c) & 0xFFFFFFFF
    H[3] = (H[3] + d) & 0xFFFFFFFF
    H[4] = (H[4] + e) & 0xFFFFFFFF
    H[5] = (H[5] + f) & 0xFFFFFFFF
    H[6] = (H[6] + g) & 0xFFFFFFFF
    H[7] = (H[7] + h) & 0xFFFFFFFF

def sha256(message):
    """
    This function implements the SHA-256 hash function to compute the hash of a message.
    """
    
    H = initial_H[:] # Copy of the initial H in order to execute the program through the tkinter window multiple times
    
    # Pre-processing the message
    message = preprocess(message)

    # Split the pre-processed message into 64 bytes (i.e 512-bit) chunks
    chunks = []
    for i in range(0, len(message), 64):
        chunks.append(message[i:i+64])    
        
    # Processing each chunk to update the hash values
    for chunk in chunks:
         chunk_processing(chunk, H, K)

    # Concatenation of the final hash values to produce the resulting 256-bit hash
    hash_value = b''
    for h in H:
        hash_value += h.to_bytes(4, byteorder='big')
    return hash_value.hex()






# 4 - Graphical interface

def compute_SHA256_hashes():
    """
    This function computes and compares the SHA-256 hash of a user-entered message using both my implementation of SHA-256 and the Python's hashlib library.
    """
    # If no message is entered, an empty string is used (as an empry string is a valid input for hashing)
    message = entry_message.get()
    message_bytes = message.encode("utf-8") 

    # Hashes computation of the message
    my_hash = sha256(message_bytes)
    library_hash = hashlib.sha256(message_bytes).hexdigest()
    
    # Comparison between the two hashes
    if my_hash == library_hash:
        match = "THE HASHES MATCH!"
        bg = "green"
    else:
        match = "THE HASHES DON'T MATCH!"
        bg = "red"
        

    # To display the results
    label_mine_hash.config(text=f"My SHA-256 is: {my_hash}")
    label_library_hash.config(text=f"Hashlib SHA-256 is: {library_hash}")
    label_match.config(bg = bg, fg = "white", text=f"{match}")




# Creation of the tkinter window
window = tk.Tk()
window.title("SHA-256 Hash")

# Entry of the message by the user
tk.Label(window, text="Enter your message:").pack()
entry_message = tk.Entry(window, width=100)
entry_message.pack()

tk.Button(window, text="Compute the SHA-256 hashes", command=compute_SHA256_hashes).pack()

# Display hashes
label_mine_hash = tk.Label(window, text="My SHA-256: ")
label_mine_hash.pack()

label_library_hash = tk.Label(window, text="Hashlib SHA-256: ")
label_library_hash.pack()

label_match = tk.Label(window)
label_match.pack()


window.mainloop()
