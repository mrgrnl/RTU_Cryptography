# Riga Technical University - Cryptography project: SHA-256 Hash Function Implementation
This project consists of an implementation of the SHA-256 hash function in Python, as well as a comparison with the standard hashlib library. 
The program includes a graphical interface using Tkinter for calculating and verifying SHA-256 hashes for messages entered by the user.

## Features
- Implementation of the SHA-256 algorithm from scratch, adhering to the SHA-256 specification (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).  
  The implementation follows these steps:  
  1 - Hash values and array of round constants  
  2 - Pre-processing (Padding)  
  3 - Compression function  
- Tkinter-based GUI  
- Comparison of the SHA-256 output with Python's hashlib implementation
- Displays whether the computed hashes match

## Requirements
- Python 3.x
- Tkinter library (usually included in Python distributionsPython distributions)
