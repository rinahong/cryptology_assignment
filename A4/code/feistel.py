#!/usr/bin/python3

# feistel.py
#
# Assignment 4, COMP 7402, Winter 2019.
#
# Usage: feistel.py [-h] [-k KEY] [-i INPUT] [-o OUTPUT] [-e] [-d] inputtype
#
# Example uses:
#   python3 feistel.py kb -k 7
#   python3 feistel.py f -k 64820 -i in.txt -o out -e
#   python3 feistel.py f -k 64820 -i out -o decrypted.txt -d
#
# Date: 2019-03-02  implement file input
#       2019-03-03  implement keyboard input, argument validation
#       2019-03-05  add thorough comments to functions
# Designer: Rina Hong, Renato Montes
# Programmer: Rina Hong, Renato Montes
#
# Copyright (c) 2019 Rina Hong, Renato Montes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import sys

#--------------------------- NUMERIC CONSTANTS --------------------------------

#Feistel cipher blocksize, in bytes.
BLOCKSIZE = 8

#Number of bits in a byte.
BITS_IN_BYTE = 8

#Number of rounds used in the Feistel cipher.
NUM_ROUNDS = 8

#The number billion.
BILLION = 1000000000

#Two to the power of thirty two minus one, i.e. 2^32 - 1.
TWO_POWER_32_MINUS_1 = 4294967295

#--------------------------- STRING CONSTANTS ---------------------------------

#Valid input types available when invoking the program from the command-line.
KEYBOARD_INPUT_TYPES = ("kb", "keyboard")
FILE_INPUT_TYPES = ("f", "file")

#------------------------ IDENTIFICATION CONSTANTS ----------------------------

#Input type.
KEYBOARD_INPUT = 1  #Command-line input with the keyboard.
FILE_INPUT = 2      #A file in the current directory.

#Cryptological action being carried out.
ENCRYPT = 1
DECRYPT = 2

#Common byte to pad plaintexts with.
#Same as 01010101 in bits, or the ASCII char 'U'.
PADBYTE = b'\x55'

#Successor block half XOR'd with the key schedule function.
#These constants are used when checking for surviving unflipped bits.
LEFT = 1
RIGHT = 2

#--------------------------- PROGRAM BEGINS ----------------------------------

class FeistelRunner():
    """Runs crytographical Feistel algorithms."""

    def __init__(self, args):
        """Init instance.
        
        Date: 2019-03-02
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            args (argparse.Namespace): object holding
                command-line arguments
        """
        if args.inputtype in KEYBOARD_INPUT_TYPES:
            self.inputtype = KEYBOARD_INPUT
        elif args.inputtype in FILE_INPUT_TYPES:
            self.inputtype = FILE_INPUT
        self.key = args.key

        if self.inputtype == FILE_INPUT:
            #input filename
            self.infile = args.input
            #output filename
            self.outfile = args.output
            if args.encrypt:
                self.action = ENCRYPT
            elif args.decrypt:
                self.action = DECRYPT
        elif self.inputtype == KEYBOARD_INPUT:
            #used to hold ciphertext for keyboard input only
            self.ciphertext = b''

    def use_keyboard(self):
        """Run with keyboard input doing both encryption and decryption.
        
        Date: 2019-03-03
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes
        """
        #encrypt, then decrypt
        self.action = ENCRYPT
        self.encrypt()
        self.action = DECRYPT
        self.decrypt()

    def encrypt(self):
        """Encrypt a plaintext.
        
        Date: 2019-03-02
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes
        """
        #get the plaintext as a bytes object
        plaintext = self.get_input_text()

        #calculate padding length, then pad the plaintext
        plain_len = len(plaintext)
        padding_len = self.get_padding_len(plain_len)
        plaintext = plaintext + (PADBYTE * padding_len)

        #encrypt the text
        ciphertext = self.transform_text(plaintext, self.encrypt_block_parts)

        #add padding_len at end of ciphertext
        ciphertext += padding_len.to_bytes(1, "big")
        
        #file or terminal output
        self.print_text(ciphertext)

    def decrypt(self):
        """Decrypt a ciphertext.
        
        Date: 2019-03-02
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes
        """
        #get the ciphertext
        ciphertext = self.get_input_text()

        #extract number of padded bytes, then cut off the last byte
        removable_bytes = ciphertext[-1]
        ciphertext = ciphertext[0:-1]

        #decrypt the text
        plaintext = self.transform_text(ciphertext, self.decrypt_block_parts)

        #remove padded bytes
        plaintext = plaintext[:-1 * removable_bytes]

        #file or terminal output
        self.print_text(plaintext)

    def transform_text(self, input_text, alter_block):
        """Transform a text by using the chosen algorithm mode.
        
        Date: 2019-03-03
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            input_text (bytes): bytes object holding the input,
                whether binary or not, encrypted or not
            alter_block (func): function to be used to alter
                blocks in the selected mode
        
        Return:
            bytes: the output plaintext or ciphertext
        """
        #transform text block by block in ECB mode
        output_text = self.ecb_transform(input_text, alter_block)

        #FUTURE: other modes will be available here in assignment 5

        return output_text

    def ecb_transform(self, input_text, alter_block):
        """Encrypt or decrypt a text in ECB mode.

        Date: 2019-03-03
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            input_text (bytes):

            alter_block (func):

        Return:
            bytes: the output plaintext or ciphertext

        Pseudo-code of the transformation:
            While there is still input text,
                grab some bytes, split them into two,
                transform them for some rounds, save the result in-memory
        """
        #object pooling
        counter = begin = end = left = right = 0
        output_text = block = b''
        text_len = len(input_text)

        while end < text_len:
            #select & split block
            begin = BLOCKSIZE * counter
            end = begin + BLOCKSIZE
            block = input_text[begin:end]
            left = int.from_bytes(block[:BLOCKSIZE // 2], byteorder="big")
            right = int.from_bytes(block[BLOCKSIZE // 2:], byteorder="big")

            #transform block
            left, right = alter_block(left, right)

            #save block
            left = left.to_bytes(BLOCKSIZE // 2, byteorder="big")
            right = right.to_bytes(BLOCKSIZE // 2, byteorder="big")
            output_text += left + right
            counter += 1
        return output_text

    def get_input_text(self):
        """Get the input text to be encrypted or decrypted.
        
        Date: 2019-03-02
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Return:
            bytes: the input plaintext or ciphertext
        """
        input_text = b''
        if self.inputtype == KEYBOARD_INPUT:
            if self.action == ENCRYPT:
                print("Enter a plaintext line:")
                try:
                    input_text = input().encode()
                except UnicodeDecodeError:
                    print("Error: keyboard input must be valid Unicode text.")
                    sys.exit(0)
                if len(input_text) == 0:
                    print("Error: please enter something.")
                    sys.exit(0)
            if self.action == DECRYPT:
                input_text = self.ciphertext
        elif self.inputtype == FILE_INPUT:
            with open(self.infile, "rb") as file_source:
                input_text = file_source.read()
        return input_text

    def get_padding_len(self, plain_len):
        """Get the required padding length of a plaintext.
        
        Date: 2019-03-0
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            plain_len (int): number of bytes of the plaintext
        
        Return:
            int: length of padding needed to be applied to plaintext

        Pre-condition:
            plain_len is a positive integer
        """
        remainder = plain_len % BLOCKSIZE
        if remainder > 0:
            return BLOCKSIZE - remainder
        elif remainder == 0:
            return BLOCKSIZE

    def encrypt_block_parts(self, left, right):
        """Encrypt a block of size BLOCKSIZE.
        
        Date: 2019-03-0
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            left (int): int representation of the first half of a block
            right (int): int representation of the latter half of a block

        Return:
            tuple, of (int, int): int representations of the encrypted first
                and latter halves of a ciphertext block
        """
        #init variables
        mixin = temp = 0 #object pooling
        changed = None
        current_side = LEFT
        counter = 1
        if self.inputtype == KEYBOARD_INPUT:
            print("------------------------------")
            changed = [False for i in range(BLOCKSIZE * BITS_IN_BYTE)]
            print("left:", hex(left), " right:", hex(right), end='\n\n')

        #carry out Feistel rounds
        while counter <= NUM_ROUNDS:
            #mixin = (counter * right + self.key) % TWO_POWER_32_MINUS_1        # <- WEAK!
            mixin = ((counter + self.key + right * BILLION)**(right % 8)) % TWO_POWER_32_MINUS_1
            temp = right
            right = left ^ mixin
            left = temp
            if self.inputtype == KEYBOARD_INPUT:
                self.show_change(counter, mixin, left, right, current_side, changed)
                current_side = RIGHT if current_side == LEFT else LEFT #toggle side
            counter += 1
        return (left, right)

    def decrypt_block_parts(self, left, right):
        """Decrypt a block of size BLOCKSIZE.
        
        Date: 2019-03-0
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            left (int):
            right (int):

        Return:
            tuple, of (int, int): int representations of the decrypted left
                and right halves of a plaintext block
        """
        mixin = temp = 0 #object pooling
        counter = NUM_ROUNDS
        while counter > 0:
            temp = right
            right = left
            #mixin = (counter * right + self.key) % TWO_POWER_32_MINUS_1       # <- WEAK!
            mixin = ((counter + self.key + right * BILLION)**(right % 8)) % TWO_POWER_32_MINUS_1
            left = temp ^ mixin
            counter -= 1
        return (left, right)

    def show_change(self, round_num, mixin, left, right, current_side, changed):
        """Show changes made in a specific round.
        
        Date: 2019-03-0
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            round_num (int): round number counter
            mixin (int): result of the key function used in the round
            left (int): int representation of  left block half of current round
            right (int): int representation of right block half of current round
            current_side (int): current side on the left in relation to original block halves
            changed (list, of bool elements): bit-positions, holding True if they have
                had their value flipped at least once
        """
        mixin_bits = bin(mixin)[2:].zfill(BLOCKSIZE * BITS_IN_BYTE // 2)
        #left_bits = bin(left)[2:].zfill(BLOCKSIZE * BITS_IN_BYTE // 2)
        flipped_this_round = offset = 0
        if current_side == RIGHT:
            offset = BLOCKSIZE * BITS_IN_BYTE // 2
        for index, elem in enumerate(mixin_bits):
            if elem == '1':
                flipped_this_round += 1
                if not changed[index + offset]:
                    changed[index + offset] = True
        flipped_so_far = changed.count(True)
        print("Round:", round_num)
        #print("right-half int value:", right)
        print("flipped positions:", mixin_bits)
        print("flipped this round:", flipped_this_round)
        print("left:", hex(left), " right:", hex(right))
        print("flipped so far:", flipped_so_far, end='\n\n')
        

    def print_text(self, output_text):
        """Output result text after encryption or decryption.
        
        Date: 2019-03-02
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes

        Args:
            output_text (bytes): the output plaintext or ciphertext

        Pre-condition:
            when using keyboard_input, it is assumed Python's decode()
            function will not fail on output_text. This could happen
            if a non-Unicode plaintext is originally fed as keyboard
            input.
        """
        if self.inputtype == FILE_INPUT:
            with open(self.outfile, "wb") as file_target:
                file_target.write(output_text)
        elif self.inputtype == KEYBOARD_INPUT:
            if self.action == ENCRYPT:
                print("Line after encryption:")
                print(str(output_text)[2:-1], end='\n\n')
                self.ciphertext = output_text
            elif self.action == DECRYPT:
                print("Line after decryption:")
                print(output_text.decode(), end='\n\n')

def exists_in_directory(filename):
    """Determine whether a filename exists in the current directory.
    
    DATE: 2019-01-20
    DESIGNER: Renato Montes
    PROGRAMMER: Renato Montes
    
    Args:
        filename (str): the filename to be examined
        
    Return:
        bool: True if the file is found, otherwise False"""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    filenames = os.listdir(project_dir)
    return filename in filenames

def validate_arguments(args):
    """Validate parsed command-line arguments.
    
    Date: 2019-03-03
    Designer: Rina Hong, Renato Montes
    Programmer: Rina Hong, Renato Montes

    Args:
        args (argparse.Namespace): object holding
            command-line arguments

    Return:
        bool: True if the arguments are valid,
            False otherwise
    """
    if args.inputtype in KEYBOARD_INPUT_TYPES:
        if not args.key:
            print("Error: a key must be provided.")
        elif args.input or args.output or args.encrypt or args.decrypt:
            print("Error: only a key is needed if using keyboard input.")
        else:
            return True
        #usage example
        print("Usage example: python3 feistel.py kb -k 1359876")
    elif args.inputtype in FILE_INPUT_TYPES:
        if not args.key:
            print("Error: a key must be provided.")
        elif not args.input:
            print("Error: a valid input filename must be provided with the flag -i.")
        elif not exists_in_directory(args.input):
            print("Error: the input file does not exist in the current directory.")
        elif os.stat(args.input).st_size == 0:
            print("Error: input file is empty.")
        elif not args.output or len(args.output) == 0:
            print("Error: a valid output filename must be provided with the flag -o.")
        elif not args.encrypt and not args.decrypt:
            print("Error: must choose between -e (encryption) or -d (decryption).")
        elif args.encrypt and args.decrypt:
            print("Error: can only choose one of -e (encryption) or -d (decryption).")
        else:
            return True
        #usage example
        print("Usage example: python3 feistel.py f -k 1359876 -i in.txt -o out.txt -e")
    else:
        print("Error: Invalid input type. Available: kb (keyboard), f (file).")
    return False

def get_arguments():
    """Obtain command-line arguments from program invocation.
    
    Date: 2019-03-02
    Designer: Rina Hong, Renato Montes
    Programmer: Rina Hong, Renato Montes

    Return:
        argparse.Namespace: object holding
            command-line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("inputtype", help="input type: kb (keyboard) or f (file)")
    parser.add_argument("-k", "--key", required=True, help="key", type=int)
    parser.add_argument("-i", "--input", help="input filename")
    parser.add_argument("-o", "--output", help="output filename")
    parser.add_argument("-e", "--encrypt", help="encrypt the file", action="store_true")
    parser.add_argument("-d", "--decrypt", help="decrypt the file", action="store_true")
    return parser.parse_args()

if __name__ == '__main__':
    """Program entry point.
    
    DATE: 2019-03-02
    DESIGNER: Rina Hong, Renato Montes
    PROGRAMMER: Rina Hong, Renato Montes"""
    #get and validate command-line arguments
    args = get_arguments()
    has_valid_args = validate_arguments(args)
    if not has_valid_args:
        sys.exit(0)

    #run program
    runner = FeistelRunner(args)
    if runner.inputtype == KEYBOARD_INPUT:
        runner.use_keyboard()
    if runner.inputtype == FILE_INPUT:
        if runner.action == ENCRYPT:
            runner.encrypt()
            print("Encryption completed.")
        elif runner.action == DECRYPT:
            runner.decrypt()
            print("Decryption completed.")

