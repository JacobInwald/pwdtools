#!/usr/bin/env python
from passwordmeter import test
from urllib.request import urlopen
from os.path import isfile
from random import choice,randint
import re
from hashlib import md5, sha1, sha256, sha384, sha512
import requests
from colorama import init, Fore, Back, Style
init(autoreset=True)
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# API functions

def hashtoolkitapi(hashvalue, hashtype):
    """API for https://hashtoolkit.com/ which is a database of md5, sha1, sha256, sha384, and sha512 hashes."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'}
    response = requests.get('https://hashtoolkit.com/decrypt-%s-hash/?hash=%s' % (hashtype, hashvalue), headers=headers).text
    match = re.search(r'/generate-hash/\?text=(.*?)"', response)
    if match:
        return match.group(1)
    else:
        return False


def nitryxgenapi(hashvalue, hashtype):
    """API for https://www.nitrxgen.net/md5db/ which is a database of md5 hashes."""
    response = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
    if response:
        return response
    else:
        return False
    

def md5decryptapi(hashvalue, hashtype):
    """API for https://md5decrypt.net/ which is a database of md5, sha1, sha256, sha384, and sha512 hashes."""
    response = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=hashbusting@gmail.com&code=dc19e9be5ce11648' % (hashvalue, hashtype)).text
    if len(response) != 0 and 'ERREUR' not in response:
        return response
    else:
        return False

# Main functions

def pwd_strength(pwd:str)->str:
    """
    Return the strength of a password.
    """
    strengths = {0: Fore.RED + 'very weak\033[0;0m', 1: Fore.RED + 'weak\033[0;0m',
                 2: Fore.RED + 'not great\033[0;0m', 3: Fore.GREEN + 'strong\033[0;0m',
                 4: Fore.GREEN + 'very strong\033[0;0m'}
    vw_grade = {'name': 0, 'minlength': 1, 'specialcharacterrange': 0, 'uppercaserange': 0, 'numberrange': 0}
    w_grade = {'name': 1, 'minlength': 5, 'specialcharacterrange': 0, 'uppercaserange': 1, 'numberrange': 0}
    m_grade = {'name': 2, 'minlength': 7, 'specialcharacterrange': 0, 'uppercaserange': 1, 'numberrange': 1}
    s_grade = {'name': 3, 'minlength': 10, 'specialcharacterrange': 1, 'uppercaserange': 2, 'numberrange': 2}
    vs_grade = {'name': 4, 'minlength': 14, 'specialcharacterrange': 2, 'uppercaserange': 2, 'numberrange': 3}
    grades = [vw_grade, w_grade, m_grade, s_grade, vs_grade]

    pwd_grades = {'minlength': 0, 'specialcharacterrange': 0, 'uppercaserange': 0, 'numberrange': 0}
    
    length = len(pwd)
    specialcharacterrange = len(re.sub('[\w]+' ,'', pwd))
    uppercaserange = len(re.sub('[^A-Z]+', '', pwd))
    numberrange = len(re.sub('[^0-9]+', '', pwd))
    # TODO: Add a check for the presence of a dictionary word in the password.
    for g in grades:
        if length >= g['minlength']:
            pwd_grades['minlength'] = g['name']
        if specialcharacterrange >= g['specialcharacterrange']:
            pwd_grades['specialcharacterrange'] = g['name']
        if uppercaserange >= g['uppercaserange']:
            pwd_grades['uppercaserange'] = g['name']
        if numberrange >= g['numberrange']:
            pwd_grades['numberrange'] = g['name']
    return strengths.get(min(pwd_grades.values()))


def pwd_generate(online:bool=True, save:bool=False)->str:
    """
    Generate a password.
    """
    # Get word list from words.txt or github
    if online:
        print('Downloading words.txt...')
        url = 'https://raw.githubusercontent.com/dwyl/english-words/master/words.txt'
        if save:
            with open('words.txt', 'w') as f:
                f.write(urlopen(url).read().decode('utf-8'))
        words = urlopen('https://raw.githubusercontent.com/dwyl/english-words/master/words.txt').read().decode('utf-8').split('\n')
    else:
        if not isfile('words.txt'):
            return False
        else:
            with open('words.txt', 'r') as f:
                words = f.read().split('\n')

    # Generate password
    words = [w for w in words if re.match('^[a-z]+$', w) and 6 >= len(w) >= 4]
    pwd = ''
    for i in range(randint(4,6)):
        w = choice(words) # choose random word
        if not randint(0,2): # randomly remove vowels and replace with numbers
            w = re.sub('a', '4', w)
            w = re.sub('i', '1', w)
            w = re.sub('e', '3', w)
            w = re.sub('o', '0', w)
        # randomly capitalize letters
        nw = ''
        w = [c.upper() if not randint(0,5) else c for c in w]
        for c in w: nw += c
        pwd += nw
        # add a random special character to the end of the word
        pwd += choice(['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '[', ']', '{', '}', ';', ':', ',', '.', '/', '?', '|'])

    return pwd


def pwd_check_hash_nosalt(pwd:str)->bool:
    """
    Checks if the passwords unsalted hash has been compromised. Note that this won't work if the password is salted.
    """
    # Initialize APIs
    apis = [hashtoolkitapi, nitryxgenapi, md5decryptapi]
    hs = {md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512'}
    secure_hs = {'md5' : True, 'sha1' : True, 'sha256' : True, 'sha384' : True, 'sha512' : True}

    # Check if password hash is compromised for each hash type
    for h in hs.keys(): 
        hashvalue = h(pwd.encode('utf-8')).hexdigest()
        print("%s check - hash value: %s..." % (hs[h], hashvalue[0:15]))
        for api in apis:
            response = api(hashvalue, hs[h])
            if response:
                print("\tHash " + Fore.RED + "found\033[0;0m in %s's database for password: %s" % (api.__name__.replace('api', ''), response))
                secure_hs[hs[h]] = False
            else:
                print("\tHash " + Fore.GREEN + "not found\033[0;0m in %s's database." % api.__name__.replace('api', ''))
                secure_hs[hs[h]] = secure_hs[hs[h]] and True

    for h in secure_hs.keys():
        if not secure_hs[h]:
            print(Style.BRIGHT + Fore.RED + "Your password is compromised in %s." % h)
        else:
            print(Style.BRIGHT + Fore.GREEN + "Your password is not compromised in %s." % h)
    return secure_hs['md5'] and secure_hs['sha1'] and secure_hs['sha256'] and secure_hs['sha384'] and secure_hs['sha512']


def bust_hash(hashvalue:str)->bool:
    """
    Checks if the hash has been compromised.
    """
    # Initialize APIs
    apis = [hashtoolkitapi, nitryxgenapi, md5decryptapi]
    hashfunctions = {'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha384': sha384, 'sha512': sha512}
    hashlengths = {32: 'md5', 40: 'sha1', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
    
    hashtype = hashlengths.get(len(hashvalue))
    h = hashfunctions.get(hashtype)
    compromised = False

    # Check if password hash is compromised for each hash type
    print("%s check - hash value: %s..." % (hashtype, hashvalue[0:15]))
    for api in apis:
        response = api(hashvalue, hashtype)
        if response:
            print("\tHash " + Fore.RED + "found\033[0;0m in %s's database, translated to: %s" % (api.__name__.replace('api', ''), response))
            compromised = True
        else:
            print("\tHash " + Fore.GREEN + "not found\033[0;0m in %s's database." % api.__name__.replace('api', ''))

    if compromised:
        print(Style.BRIGHT + Fore.RED + "Hash is compromised.")
    else:
        print(Style.BRIGHT + Fore.GREEN + "Hash is not compromised.")
    return compromised


def to_hash(v:str, method:str)->str:
    """
    Returns the hash of a string.
    """
    hashfunctions = {'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha384': sha384, 'sha512': sha512}
    h = hashfunctions.get(method)
    if h:
        return h(v.encode('utf-8')).hexdigest()
    else:
        return False