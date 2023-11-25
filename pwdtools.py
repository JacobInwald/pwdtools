import sys
from pwdlib import *
from os.path import isfile

if sys.argv[1] == '-check' or sys.argv[1] == '-c':
    if len(sys.argv) == 2:
        print("Your password is " + pwd_strength(sys.argv[2]))
    else:
        sys.exit('No password specified. Please specify a password.')
elif sys.argv[1] == '-generate' or sys.argv[1] == '-g':
    if isfile('words.txt'):
        print(pwd_generate(False, False))
    else:
        print(pwd_generate(True, False))
elif sys.argv[1] == '-checkhash':
    print('Generating...')
