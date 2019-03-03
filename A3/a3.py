#!/usr/bin/python3.5

# Prompt user inputs for plain text type, plain text, key and output file name
#myMessage = 'A wilderness of mirrors'
#myKey = 12

import sys, getopt, random

def main (argv):

    try:
        opts, args = getopt.getopt (argv, "hi:t:k:f:",["inputType=","ptext=", "key=", "cfile="])

    except getopt.getoptError:
        sys.exit (1)

    if len (sys.argv[1:]) < 8:
        print ('Usage: python3 te.py -i <plainTextInputType s/f> -t <plaintextfilename> -k <key> -f <ciphertextfilename>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('Usage: python3 te.py -i <plainTextInputType s/f> -t <plaintextfilename> -k <key> -f <ciphertextfilename>')
            sys.exit ()
        elif opt in ("-i", "--inputType"):
            if(arg != 's' and arg != 'f'):
                print ('-i argument only accepts s for plaintext string input or f for plaintext filename input')
                sys.exit ()
            inputType = arg
        elif opt in ("-t", "--ptext"):
            ptext = arg
        elif opt in ("-k", "--key"):
            key = arg
        elif opt in ("-f", "--cfile"):
            ctextFileName = arg

    plainText = getText(inputType, ptext)
    randArr = generateRand(len(plainText))
    print(randArr)
    otpCipherText = ecryptWithOTP(randArr, plainText)
    print("otp cipher: ",otpCipherText)
    realKey = getKey(key, len(plainText))

    xorCipherText = ecryptWithXOR(realKey, otpCipherText)
    print("xor cipher: ",xorCipherText)

    cipherFile = open (ctextFileName, "w")
    cipherFile.write(xorCipherText)
    cipherFile.close()

#Return the plainText in String
def getText(textOption, plainText):
    if(textOption == 's'):
        return plainText
    else:
        plainTextFile = open(plainText)
        readPlanTextFile = plainTextFile.read()
        return readPlanTextFile

#Generate random numbers and return in an array
def generateRand(textLen):
    randomNumArr = []
    while(textLen != 0):
        randomNumArr.append(random.randint(40,100))
        textLen = textLen - 1
    return randomNumArr

# get calculated key from userinput
# This is written for the case where key length and plain text length are different
def getKey(key, plainTextLen):
    division = plainTextLen // len(key)
    modulo = plainTextLen % len(key)
    return key * division + key[:modulo]

# Encrypt plainText with otp
def ecryptWithOTP(randomNumArr, plainText):
    cipherText = []
    return ''.join(chr(ord(a) + b) for a,b in zip(plainText,randomNumArr))

# Encrypt OTP ciphered text with XOR and given key
def ecryptWithXOR(key,otpCipherText):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(key,otpCipherText))


# If a3.py is run (instead of imported as a module) call
# the main() function.
if __name__ == "__main__":
    main (sys.argv[1:])
