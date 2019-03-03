#!/usr/bin/python3.5

# Detect English module
# Provides all of the functions needed to find dictionary words

import sys

UpperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
Alphabet = UpperCase + UpperCase.lower() + ' \t\n'

# Store all words in "dictionary.txt" into array and return it.
def loadDictionary():
    dictionaryFile = open ('dictionary.txt')
    englishWords = dictionaryFile.read().split('\n')
    dictionaryFile.close()
    return englishWords

# Remove all the non-letter characters from the string
def removeNonLetters (message):
    lettersOnly = []
    for symbol in message:
        if symbol in Alphabet:
            lettersOnly.append (symbol)
    return ''.join (lettersOnly)



# Loop through all possible words which is attepted decrypted string.
# And check if there is any word match found with dictionary wordsself.
# If found, prompt the user to continue attacking for the next key or stop the program.
def FindEnglish (message):
    WordList = loadDictionary()
    message = message.upper()
    message = removeNonLetters (message)
    possibleWords = message.split()

    if possibleWords == []:
        return 0.0 # no matches found

    option = ""
    for word in possibleWords:
        if word in WordList:
            print("Word match found --> ", word)
            print("Here is your first 50 characters: ", message[0:50])
            option = input("Press enter key to continue the attach or y to stop: ")
            while option != '' and option != 'y':
                option = input("Your option is enter key or y: ")
            if option == '':
                return True
            else:
                sys.exit ()

    return False
