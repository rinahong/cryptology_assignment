#!/usr/bin/python3

# bitdiff.py
#
# Diffs bytes objects. Works best with short texts.
#
# Usage: python3 bitdiff.py filename1 filename2
#
# Date: 2019-03-05
# Designer: Renato Montes
# Programmer: Renato Montes
#
# Copyright (c) 2019 Renato Montes
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

"""Examines the differences in bits of two input sources."""

#Number of bits in a byte
BITS_IN_BYTE = 8



#---USING HARDCODED BYTE OBJECTS---

##hello with key 8
##\xc0 t W  <    \x88 @ \n   l \x03'
#byte_obj_1 = b'\xc0tW<\x88@\nl\x03' 

##hello with key 9
##\xbe R \r \x08 \r   m \xce @ \x03'
#byte_obj_2 = b'\xbeR\r\x08\rm\xce@\x03' 



#---USING FILES IN CURRENT DIRECTORY---
import sys

if len(sys.argv) != 3:
    print("Usage: python3 bitdiff.py file1 file2")
    sys.exit(0)

#from files
f1 = open(sys.argv[1], "rb")
byte_obj_1 = f1.read()
f1.close()
f2 = open(sys.argv[2], "rb")
byte_obj_2 = f2.read()
f2.close()



#---EXAMINATION---

#reformat for XOR operation
cipher_int_1 = int.from_bytes(byte_obj_1, byteorder="big")
cipher_int_2 = int.from_bytes(byte_obj_2, byteorder="big")
result = cipher_int_1 ^ cipher_int_2

#compare cipher lengths
len_1 = len(byte_obj_1)
len_2 = len(byte_obj_2)
greater_len = len_1 if len_1 > len_2 else len_2

#reformat for bit comparison
result = bin(result)[2:] #[2:] to remove leading 0b characters
result = result.count('1')

print(result, "bits are different")
print("byte lengths: file1", str(len_1), "bytes  file2", str(len_2), "bytes")
