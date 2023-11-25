#!/usr/bin/env python3
import sys
from pwdlib.pwdlib import *
from os.path import isfile

if len(sys.argv) == 1:
    sys.exit('No option specified. Please specify an option. Use --help for more information.')

if sys.argv[1] == '--check' or sys.argv[1] == '-c':
    if len(sys.argv) == 3:
        print("Your password is " + pwd_strength(sys.argv[2]))
    else:
        sys.exit('No password specified. Please specify a password.')
elif sys.argv[1] == '--generate' or sys.argv[1] == '-g':
    if isfile('words.txt'):
        print(pwd_generate(False, False))
    else:
        print(pwd_generate(True, False))
elif sys.argv[1] == '--checkhash' or sys.argv[1] == '-ch':
    if len(sys.argv) == 3:
        pwd_check_hash_nosalt(sys.argv[2])
    else:
        sys.exit('No password specified. Please specify a password.')
elif sys.argv[1] == '--busthash' or sys.argv[1] == '-bh':
    if len(sys.argv) == 3:
        bust_hash(sys.argv[2])
    else:
        sys.exit('No hash given. Please specify a hash.')
elif sys.argv[1] == '--hash' or sys.argv[1] == '-h':
    if len(sys.argv) == 4:
        h = to_hash(sys.argv[2], sys.argv[3])
        if h: 
            print(h)
        else:
            print('Invalid hash type. Supported hash types are: md5, sha1, sha256, sha384, sha512.')
    else:
        sys.exit('Wrong number of arguments. Correct usage: pwdtools --hash <string> <hash type>')
elif sys.argv[1] == '--help':
    print('''
    Usage: pwdtools [OPTION] [PARAMETERS]
    Perform various password-related tasks.
    
    Options:
        -c, --check         Check the strength of a password.
        -g, --generate      Generate a password, doesn't need an extra input.
        -ch, --checkhash    Check the strength of a password hash.
        -bh, --busthash     Bust a hash, attempting to reverse the hashing procedure.
        -h, --hash          Hashes a string, given the string and hash type. 
                            Supported hash types: md5, sha1, sha256, sha384, sha512. 
        --help          Display this help message.
    ''')
    sys.exit()

