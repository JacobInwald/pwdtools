import sys
from pwdlib import *

if sys.argv[1] == '-check':
    print("Your password is " + pwd_strength(sys.argv[2]))
elif sys.argv[1] == '-generate':
    print('Cleaning...')
elif sys.argv[1] == '-checkhash':
    print('Generating...')
