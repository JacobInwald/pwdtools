#!/usr/bin/env python3

import sys
from pwdtools_src.pwdlib import *


if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.exit('No option specified. Please specify an option. Use --help for more information.')

    if sys.argv[1] == '--check' or sys.argv[1] == '-c':
        if len(sys.argv) == 3:
            print("Your password is " + pwd_strength(sys.argv[2]))
        else:
            sys.exit('No password specified. Please specify a password.')

    elif sys.argv[1] == '--generate' or sys.argv[1] == '-g':
        print(pwd_generate())

    elif sys.argv[1] == '--hash' or sys.argv[1] == '-h':
        if len(sys.argv) == 4:
            h = to_hash(sys.argv[2], sys.argv[3])
            if h: 
                print(h)
            else:
                print('Invalid hash type. Supported hash types are: md5, sha1, sha256, sha384, sha512.')
        else:
            sys.exit('Wrong number of arguments. Correct usage: pwdtools --hash <string> <hash type>')

    elif sys.argv[1] == '--search' or sys.argv[1] == '-s':
        if len(sys.argv) == 3:
            pwd_search_online(sys.argv[2])
        else:
            sys.exit('No password specified. Please specify a password.')

    elif sys.argv[1] == '--searchhash' or sys.argv[1] == '-sh':
        if len(sys.argv) == 3:
            search_hash_online(sys.argv[2])
        else:
            sys.exit('No hash given. Please specify a hash.')

    elif sys.argv[1] == '--busthash' or sys.argv[1] == '-bh':
        if len(sys.argv) == 3:
            if not pwd_crack(sys.argv[2]): sys.exit('No hash given. Please specify a hash.')
        else:
            sys.exit('No hash given. Please specify a hash.')

    elif sys.argv[1] == '--help':
        print('''
        Usage: pwdtools [OPTION] [PARAMETERS]
        Perform various password-related tasks.
        
        Options:
            -c, --check         Check the strength of a password.
            -g, --generate      Generate a password, doesn't need an extra input.
            -h, --hash          Hashes a string, given the string and hash type. 
            -s, --search        Check if a password has been leaked online.
            -bh, --busthash     Bust a hash, attempting to reverse the hashing procedure.
            -sh, --searchhash   Search for a hash in a database of hashes.
                                Supported hash types: md5, sha1, sha256, sha384, sha512. 
            --help          Display this help message.
        ''')
        sys.exit()


# TODO: Add support for password cracking
# TODO: Add encryption/decrpytion support
# TODO: ADD support for encrypting a file with a password
# TODO: Add support for public key generation