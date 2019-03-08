#!/usr/bin/python3

# feistel_test.py
#
# Unit test suite for feistel.py.
#
# Date: 2019-03-07
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

import unittest
from unittest import mock
from unittest.mock import patch

import io

import feistel

FILE_ENCRYPT = 1
FILE_DECRYPT = 2
KEYBOARD = 3

class FeistelRunnerTest(unittest.TestCase):
    """Test file encryption.
    
    Date: 2019-03-07
    Designer: Rina Hong, Renato Montes
    Programmer: Rina Hong, Renato Montes
    """

    class ValidRunnerArgs():
        """Hold valid arguments to invoke FeistelRunner with.

        Date: 2019-03-07
        Designer: Rina Hong, Renato Montes
        Programmer: Rina Hong, Renato Montes
        """
        def __init__(s, inputtype):
            s.key = 123
            if inputtype == FILE_ENCRYPT:
                s.inputtype = 'f'
                s.input = 'in.txt'
                s.output = 'out'
                s.encrypt = True
                s.decrypt = None
            elif inputtype == FILE_DECRYPT:
                s.inputtype = 'f'
                s.input = 'out'
                s.output = 'final.txt'
                s.encrypt = None
                s.decrypt = True
            elif inputtype == KEYBOARD:
                s.inputtype = 'kb'
                s.input = s.output = s.encrypt = s.decrypt = None

    @classmethod
    def setUpClass(cls):
        cls.left0 = int.from_bytes(b'abcd', byteorder="big")
        cls.right0 = int.from_bytes(b'efUU', byteorder="big")
        cls.left8 = int.from_bytes(b'qrst', byteorder="big")
        cls.right8 = int.from_bytes(b'wxyz', byteorder="big")

    def setUp(s):
        s.kb = feistel.FeistelRunner(s.ValidRunnerArgs(KEYBOARD))
        s.f_enc = feistel.FeistelRunner(s.ValidRunnerArgs(FILE_ENCRYPT))
        s.f_dec = feistel.FeistelRunner(s.ValidRunnerArgs(FILE_DECRYPT))

    # --------------------- test ecb_transform() --------------------------

    @patch('feistel.NUM_ROUNDS', 1) #speed up the transform
    def test_ecb_transform_return_is_type_bytes(s):
        inp = s.f_enc.ecb_transform(b'abcdefgh', lambda x, y: (x - 1, y - 1))
        s.assertEqual(type(inp), bytes)

    @patch('feistel.NUM_ROUNDS', 1) #speed up the transform
    def test_ecb_transform_calls_alter_block_callback_with_ints(s):
        callback_mock = mock.MagicMock(return_value=(100, 200))
        inp = s.f_enc.ecb_transform(b'abcdefgh', callback_mock)
        args, kwargs = callback_mock.call_args
        s.assertEqual(len(args), 2)
        s.assertEqual(type(args[0]), int)
        s.assertEqual(type(args[1]), int)

    @patch('feistel.NUM_ROUNDS', 1)
    def test_ecb_transform_joins_both_block_halves(s):
        inp = s.f_enc.ecb_transform(b'abcdefgh', lambda x, y: (15, 7))
        s.assertEqual(inp[2:4], b'\x00\x0f')

    # -------------------- test get_input_text() --------------------------

    @patch('builtins.print')
    @patch('builtins.input', side_effect=['my_text_input'])
    def test_smoke_get_input_text_valid_keyboard_input(s, input_func, print_func):
        s.kb.action = feistel.ENCRYPT
        inp = s.kb.get_input_text()
        s.assertEqual(inp, b'my_text_input')

    @patch('sys.stdout', new_callable=io.StringIO)
    @patch('builtins.input', side_effect=['my_text_input'])
    def test_get_input_text_keyboard_input_show_prompt(s, input_func, out_stream):
        s.kb.action = feistel.ENCRYPT
        inp = s.kb.get_input_text()
        s.assertGreater(out_stream.getvalue().find('Enter'), -1)

    @patch('builtins.print')
    @patch('builtins.input', side_effect=['my_text_input'])
    def test_get_input_text_return_is_type_bytes(s, input_func, print_func):
        s.kb.action = feistel.ENCRYPT
        inp = s.kb.get_input_text()
        s.assertEqual(type(inp), bytes)

    @patch('sys.exit')
    @patch('sys.stdout', new_callable=io.StringIO)
    @patch('builtins.input', side_effect=[''])
    def test_get_input_text_empty_keyboard_input(s, input_func, out_stream, exit_func):
        s.kb.action = feistel.ENCRYPT
        inp = s.kb.get_input_text()
        s.assertGreater(out_stream.getvalue().find('Error:'), -1)
        s.assertEqual(exit_func.called, True)

    def test_get_input_text_keyboard_input_decryption(s):
        s.kb.action = feistel.DECRYPT
        s.kb.ciphertext = b'abcd'
        inp = s.kb.get_input_text()
        s.assertEqual(inp, b'abcd')
    
    def test_get_input_text_uses_rb_mode_in_file_input(s):
        open_func = mock.mock_open(read_data='abcdefgh')
        with patch('feistel.open', open_func):
            s.f_enc.get_input_text()
            args, kwargs = open_func.call_args
            s.assertEqual(type(args[0]), str)
            s.assertEqual(args[1], "rb")

    # -------------------- test get_padding_len() -------------------------

    def test_get_padding_len_multiple_of_8(s):
        pad_len = s.f_enc.get_padding_len(256)
        s.assertEqual(pad_len, 8)
    
    def test_get_padding_len_odd_num_not_multiple_of_8(s):
        pad_len = s.f_enc.get_padding_len(5)
        s.assertEqual(pad_len, 3)
    
    def test_get_padding_len_even_num_not_multiple_of_8(s):
        pad_len = s.f_enc.get_padding_len(62)
        s.assertEqual(pad_len, 2)

    def test_get_padding_len_return_is_type_int(s):
        pad_len = s.f_dec.get_padding_len(45)
        s.assertEqual(type(pad_len), int)

    def test_get_padding_len_bytes_input(s):
        s.assertRaises(TypeError, s.f_enc.get_padding_len, b'abcd')

    # ------------------ test encrypt_block_parts() -----------------------

    @patch('feistel.NUM_ROUNDS', 1)
    def test_encrypt_block_right1_eq_left0_one_round(s):
        left1, right1 = s.f_enc.encrypt_block_parts(s.left0, s.right0)
        s.assertEqual(left1, s.right0, "encrypted L[1] not same as R[0]")

    @patch('feistel.NUM_ROUNDS', 1)
    def test_encrypt_block_right1_ne_left1_one_round(s):
        left1, right1 = s.f_enc.encrypt_block_parts(s.left0, s.right0)
        s.assertNotEqual(right1, s.left0)
    
    @patch('feistel.NUM_ROUNDS', 2)
    def test_encrypt_block_right2_ne_right0_two_rounds(s):
        left2, right2 = s.f_enc.encrypt_block_parts(s.left0, s.right0)
        s.assertNotEqual(right2, s.right0)

    @patch('feistel.NUM_ROUNDS', 1)
    def test_encrypt_block_returns_are_type_int(s):
        left1, right1 = s.f_enc.encrypt_block_parts(s.left0, s.right0)
        s.assertEqual(type(right1), int)

    # ------------------ test decrypt_block_parts() -----------------------

    @patch('feistel.NUM_ROUNDS', 1)
    def test_decrypt_block_right1_eq_left0_one_round(s):
        left7, right7 = s.f_dec.decrypt_block_parts(s.left8, s.right8)
        s.assertEqual(right7, s.left8)

    @patch('feistel.NUM_ROUNDS', 1)
    def test_decrypt_block_right1_ne_left1_one_round(s):
        left7, right7 = s.f_dec.decrypt_block_parts(s.left8, s.right8)
        s.assertNotEqual(left7, s.right8)
    
    @patch('feistel.NUM_ROUNDS', 2)
    def test_decrypt_block_right2_ne_right0_two_rounds(s):
        left6, right6 = s.f_dec.decrypt_block_parts(s.left8, s.right8)
        s.assertNotEqual(left6, s.left8)

    @patch('feistel.NUM_ROUNDS', 1)
    def test_decrypt_block_returns_are_type_int(s):
        left7, right7 = s.f_dec.decrypt_block_parts(s.left8, s.right8)
        s.assertEqual(type(left7), int)
 
    # --------------------- test print_text() --------------------------

    def test_print_text_opens_file_in_wb_mode(s):
        open_func = mock.mock_open()
        with patch('feistel.open', open_func):
            s.f_enc.print_text(b'abcdefgh')
        args, kwargs = open_func.call_args
        s.assertEqual(len(args), 2)
        s.assertEqual(type(args[0]), str)
        s.assertEqual(args[1], "wb")

    @patch('builtins.print')
    def test_print_text_saves_ciphertext_to_propert_after_encrypting(s, print_func):
        s.kb.action = feistel.ENCRYPT
        encrypted = b'wxyz0406'
        s.kb.print_text(encrypted)
        s.assertEqual(type(s.kb.ciphertext), bytes)
        s.assertEqual(s.kb.ciphertext, encrypted)

    @patch('builtins.print')
    def test_print_text_shows_plaintext_as_unicode_text_after_decrypting(s, print_func):
        s.kb.action = feistel.DECRYPT
        decrypted = b'abcdefgh'
        s.kb.print_text(decrypted)
        args, kwargs = print_func.call_args
        s.assertEqual(type(args[0]), str)
        s.assertEqual(args[0], 'abcdefgh')

    # ------------------ test validate_arguments() -----------------------

    def test_validate_arguments_valid_file_encryption_args(s):
        args = mock.Mock()
        args.inputtype = 'f'
        args.key = 123
        args.input = "in.txt"
        args.output = "out"
        args.encrypt = True
        args.decrypt = None
        result = feistel.validate_arguments(args)
        s.assertEqual(result, True)

    def test_validate_arguments_valid_file_decryption_args(s):
        args = mock.Mock()
        args.inputtype = 'f'
        args.key = 123
        args.input = "out"
        args.output = "final.txt"
        args.encrypt = False
        args.decrypt = True
        result = feistel.validate_arguments(args)
        s.assertEqual(result, True)
    
    def test_validate_arguments_valid_keyboard_input_args(s):
        args = mock.Mock()
        args.inputtype = 'kb'
        args.key = 123
        args.input = args.output = args.encrypt = args.decrypt = None
        result = feistel.validate_arguments(args)
        s.assertEqual(result, True)

    @patch('builtins.print')
    def test_validate_arguments_no_key_for_keyboard_input(s, print_func):
        args = mock.Mock()
        args.inputtype = 'kb'
        args.key = args.input = args.output = args.encrypt = args.decrypt = None
        result = feistel.validate_arguments(args)
        s.assertEqual(result, False)

    @patch('builtins.print')
    def test_validate_arguments_no_key_for_file_encryption(s, print_func):
        args = mock.Mock()
        args.inputtype = 'f'
        args.key = None
        args.input = "in.txt"
        args.output = "out"
        args.encrypt = True
        args.decrypt = None
        result = feistel.validate_arguments(args)
        s.assertEqual(result, False)

    @patch('builtins.print')
    def test_validate_arguments_empty_input_file(s, print_func):
        args = mock.Mock()
        args.inputtype = 'f'
        args.key = 123
        args.input = "in.txt"
        args.output = "out"
        args.encrypt = True
        args.decrypt = None

        file_stats = type('', (object,), {"st_size": 0})()
        patcher = patch('os.stat', lambda x: file_stats)
        patcher.start()
        result = feistel.validate_arguments(args)
        patcher.stop()
        s.assertEqual(result, False)

if __name__ == '__main__':
    """Program entry point."""
    unittest.main()


