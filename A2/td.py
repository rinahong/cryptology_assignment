#!/usr/bin/python3.5

# Transposition Cipher Decryption

import detectEnglish, math, sys, getopt

def main (argv):
    # Expecting user input arguments for ciphertext input type and filename or ciphertext.
    # Valid ciphertext input type is 's' for string or 'f' for file
    # Filename should include file extension i.e. "xxx.txt"
    try:
        opts, args = getopt.getopt (argv, "hi:t:", ["inputType=","ctext="])

    except getopt.getoptError:
        sys.exit (1)

    if len (sys.argv[1:]) < 4:
        print ('Usage: python3 td.py -i <inputType s/f> -t <ciphertext>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: python3 td.py -i <inputType s/f> -t <ciphertext>')
            sys.exit ()
        elif opt in ("-i", "--inputType"):
            if(arg != 's' and arg != 'f'):
                print ('-i argument only accepts s for cipher string or f for cipher filename')
                sys.exit ()
            inputType = arg
        elif opt in ("-t", "--ctext"):
            ctext = arg

    if inputType == 's':
        ciphertext = ctext
    else:
        cipherTextFile = open (ctext)
        cipherText = cipherTextFile.read()

    # Decrypt the ciphered text with every possible key and find a word match in dictionary.
    for keylen in range(1, len(cipherText) + 1):
        print("keylen: ", keylen)
        plaintext = decryptMessage (keylen, cipherText)
        detectEnglish.FindEnglish(plaintext)

#--------------------------------------------------------------------------------------

 # The transposition decrypt function will simulate the "columns" and
 # "rows" of the grid that the plaintext is written on by using a list
 # of strings. First, we need to calculate a few values.

def decryptMessage(key, message):
    # Determine the number of columns
    nCols = math.ceil (len (message) / key)

    # Determine the number of rows
    nRows = key

    # Determine the unused cells
    nUnused = (nCols * nRows) - len(message)

    # Each string in plaintext represents a column in the grid.
    plaintext = [''] * nCols

    # row and col point to the location of the next character in the ciphertext
    row = col = 0

    for symbol in message:
        plaintext[col] += symbol
        col += 1 # point to next column

        # If it reaches the last column in the row, or at an unused cell, start processing the next row
        if (col == nCols) or (col == nCols - 1 and row >= nRows - nUnused):
            col = 0
            row += 1

    return ''.join(plaintext)


# main() function
if __name__ == "__main__":
    main (sys.argv[1:])
