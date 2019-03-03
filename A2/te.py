#!/usr/bin/python3.5

# Transposition Cipher Encryption
#myMessage = 'A wilderness of mirrors'
#myKey = 12

import sys, getopt

def main (argv):

    try:
        opts, args = getopt.getopt (argv, "hi:t:k:f:",["inputType=","ptext=", "keysize=", "cfile="])

    except getopt.getoptError:
        sys.exit (1)

    if len (sys.argv[1:]) < 8:
        print ('Usage: python3 te.py -i <plainTextInputType s/f> -t <plaintextfilename> -k <keysize> -f <ciphertextfilename>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: python3 te.py -i <plainTextInputType s/f> -t <plaintextfilename> -k <keysize> -f <ciphertextfilename>')
            sys.exit ()
        elif opt in ("-i", "--inputType"):
            if(arg != 's' and arg != 'f'):
                print ('-i argument only accepts s for plaintext string input or f for plaintext filename input')
                sys.exit ()
            inputType = arg
        elif opt in ("-t", "--ptext"):
            ptext = arg
        elif opt in ("-k", "--keysize"):
            keylen = int (arg)
        elif opt in ("-f", "--cfile"):
            ctextFileName = arg

    if inputType == 's':
        # call the crypto function
        ciphertext = encryptMessage (keylen, ptext)
    else:
        plainTextFile = open (ptext)
        ciphertext = encryptMessage (keylen, plainTextFile.read())

    cipherFile = open (ctextFileName, "w")

    cipherFile.write(ciphertext)

    cipherFile.close()


def encryptMessage (key, message):

    # Each string in ciphertext represents a column in the grid.
    ciphertext = [''] * key

    # Iterate through each column in ciphertext.
    for col in range (key):
        pointer = col

        # process the complete length of the plaintext
        while pointer < len (message):
            # Place the character at pointer in message at the end of the
            # current column in the ciphertext list.
            ciphertext[col] += message[pointer]

            # move pointer over
            pointer += key

    # Convert the ciphertext list into a single string value and return it.
    return ''.join (ciphertext)


# If transpositionEncrypt.py is run (instead of imported as a module) call
# the main() function.
if __name__ == "__main__":
    main (sys.argv[1:])
