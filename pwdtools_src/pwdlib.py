#!/usr/bin/env python3

import re, tqdm, requests
from os.path import isfile
from random import choice,randint
from hashlib import md5, sha1, sha256, sha384, sha512
from colorama import init, Fore, Back, Style
from urllib3.exceptions import InsecureRequestWarning
from itertools import permutations
from nltk.corpus import words
import nltk, math
import numpy as np
import time
from multiprocessing import Pool
import multiprocessing as mp


# ! Global Setup
if words.words() == []:
    print("Downloading nltk words...")
    nltk.download('words')
init(autoreset=True)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
API_LIST = [None, None, None]
HASH_TYPES = {'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha384': sha384, 'sha512': sha512}
HASH_LENGTHS = {32: 'md5', 40: 'sha1', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
DATA_PATH = 'pwdtools_src/data/'
CHARACTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]:,./\\<>?'

# ! API functions

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
    
API_LIST = [hashtoolkitapi, nitryxgenapi, md5decryptapi]

def get_hash_type(hashvalue:str)->str:
    """
    Returns the hash type of a hash.
    """
    return HASH_LENGTHS.get(len(hashvalue))


# ! Password functions

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


def pwd_generate()->str:
    """
    Generate a password.
    """
    # Gets the norvig dictionary
    words = create_english_corpus()

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
        pwd += choice(['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+'])

    return pwd


# ! Hash related stuff

def pwd_search_online(pwd:str)->bool:
    """
    Checks if the passwords unsalted hash has been compromised. Note that this won't work if the password is salted.
    """
    # Initialize APIs
    secure_hs = {k:True for k in HASH_TYPES.keys()}

    # Check if password hash is compromised for each hash type
    for hash_name in HASH_TYPES.keys(): 
        hashvalue = HASH_TYPES.get(hash_name)(pwd.encode('utf-8')).hexdigest()
        print("%s check - hash value: %s..." % (hash_name, hashvalue[0:15]))
        for api in API_LIST:
            response = api(hashvalue, hash_name)
            if response:
                print("\tHash " + Fore.RED + "found\033[0;0m in %s's database for password: %s" % (api.__name__.replace('api', ''), response))
                secure_hs[hash_name] = False
            else:
                print("\tHash " + Fore.GREEN + "not found\033[0;0m in %s's database." % api.__name__.replace('api', ''))
                secure_hs[hash_name] = secure_hs[hash_name] and True

    for h in secure_hs.keys():
        if not secure_hs[h]:
            print(Style.BRIGHT + Fore.RED + "Your password is compromised in %s." % h)
        else:
            print(Style.BRIGHT + Fore.GREEN + "Your password is not compromised in %s." % h)
    return all(secure_hs.values())


def search_hash_online(hashvalue:str)->bool:
    """
    Checks if the hash has been compromised.
    """
    
    hashtype = get_hash_type(hashvalue)
    compromised = False

    # Check if password hash is compromised for each hash type
    print("%s check - hash value: %s..." % (hashtype, hashvalue[0:15]))
    for api in API_LIST:
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
    return response


def to_hash(v:str, method:str)->str:
    """
    Returns the hash of a string.
    """
    h = HASH_TYPES.get(method)
    if h:
        return h(v.encode('utf-8')).hexdigest()
    else:
        return False


# ! Attacks 

def dictionary_attack(hash:str,hash_type:str)->bool:
    """
    Attempts to crack the password using a dictionary attack.
    """
    print("Loading dictionaries...")
    dictionary_urls = { # Common passwords and leaked passwords from the SecLists repository
                        'top_10_mil'  : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords.txt",
                        'bible_1'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part01.txt",
                        'bible_2'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part02.txt",
                        'bible_3'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part03.txt",
                        'bible_4'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part04.txt",
                        'bible_5'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part05.txt",
                        'bible_6'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part06.txt",
                        'bible_7'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part07.txt",
                        'bible_8'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part08.txt",
                        'bible_9'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part09.txt",
                        'bible_10'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part10.txt",
                        'bible_11'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part11.txt",
                        'bible_12'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part12.txt",
                        'bible_13'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part13.txt",
                        'bible_14'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part14.txt",
                        'bible_15'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part15.txt",
                        'bible_16'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part16.txt",
                        'bible_17'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/BiblePass/BiblePass_part17.txt",
                        'fabian'      : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Honeypot-Captures/multiplesources-passwords-fabian-fingerle.de.txt",
                        'nordvpn'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/NordVPN.txt",
                        'google'      : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/alleged-gmail-passwords.txt",
                        'faithwriter' : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/faithwriters.txt",
                        'fortinet'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/fortinet-2021_passwords.txt",
                        'hotmail'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/hotmail.txt",
                        'myspace'     : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/myspace.txt",
                        'md5uk'       : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/md5decryptor-uk.txt",
                        '1337'        : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Permutations/1337speak.txt", 
                        'p@55w0rd'    : "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Permutations/korelogic-password.txt",
                        }
    
    dictionaries = {k : requests.get(v).text.split('\n') for k,v in tqdm.tqdm(dictionary_urls.items())}

    # Get hash function
    h = HASH_TYPES.get(hash_type)
    if not h: return False

    # Check if rockyou.txt is present and use that to begin with
    if isfile('rockyou.txt'):
        with open('rockyou.txt', 'r', encoding='latin-1') as f:
            rockyou = f.read().split('\n')
        for w in rockyou:
            if h(w.encode('utf-8')).hexdigest() == hash:
                return w
    
    # Start dictionary attack
    print("Starting Dictionary Attack...")
    for dictionary in tqdm.tqdm(dictionaries.values()):
        for w in dictionary:
            if h(w.encode('utf-8')).hexdigest() == hash:
                return w
            
    return False


def permute(word:str,suffixes:list)->list:
    """
    Returns a list of permutations of a password i.e. adding numbers or special characters to the end and 1337 speak.
    """
    
    words = []
    for suf in suffixes:
        words.append(word + suf)
        words.append(suf + word)
        if word[0].isupper():
            words.append(word[0].lower() + word[1:] + suf)
            words.append(suf + word[0].lower() + word[1:])
        else:
            words.append(word.capitalize() + suf)
            words.append(suf + word.capitalize())
    return words


def gen_suffixes(n_size:int=3, s_size:int=1)->list:
    """
    Generates a list of suffixes to be used for a permuted dictionary attack.
    """
    assert n_size >= 1 and s_size >= 1, "n_size and s_size must be greater than or equal to 1."

    n = [str(i) for i in range(10)]
    n_perms = [''] + [''.join(j) for i in range(1,n_size + 1) for j in  permutations(n, i)] + \
              [''.join([j for i in range(1,x)]) for x in range(3,n_size+2) for j in n]
    special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '?']
    special_perms = [''] + [''.join(j) for i in range(1,s_size+1) for j in  permutations(special_chars, i)] + \
                    [''.join([j for i in range(1,x)]) for x in range(3,s_size+2) for j in special_chars]
    
    suffixes = [''.join([n_suf, s_suf]) for n_suf in n_perms for s_suf in special_perms]
    suffixes += [''.join([s_suf, n_suf]) for n_suf in n_perms for s_suf in special_perms]

    return suffixes


def create_english_corpus(save:bool=True, regenerate:bool=False):
    """
    Creates a corpus of English words at least 4 letters long.
    """
    # Check if corpus exists
    if isfile(DATA_PATH+'corpus.txt') and not regenerate:
        with open(DATA_PATH+'corpus.txt', 'r') as f:
            data = f.read().split('\n')
            if len(data) > 10000:
                return data
            else:
                print("Corpus is too small, regenerating...")

    print("Downloading sources...")
    dictionary_urls = { 'norvig'        : 'http://norvig.com/ngrams/count_1w.txt',
                        'wiki'          : 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Wikipedia/wikipedia_en_vowels_no_compounds_top-1000000.txt',
                        'norvig-scrab2' : 'http://norvig.com/ngrams/sowpods.txt',
                        }
    dictionaries = {'nltk': words.words()}

    for name, url in tqdm.tqdm(dictionary_urls.items()):
        d = requests.get(url).text.split('\n')
        if name == 'norvig':
            d = [w.split('\t')[0].strip() for w in d]
        dictionaries[name] = d
    
    print("Compiling corpus...")
    corpus = set()
    # Remove words that are less than 4 letters long or contain non-alphabetic characters
    for d in dictionaries.values():
        for w in tqdm.tqdm(d):
            if len(w) < 5 or \
                not re.match('^[a-zA-Z]+$', w):
                continue
            corpus.add(w.lower())
    corpus = list(corpus)

    if save:
        with open(DATA_PATH+'corpus.txt', 'w') as f:
            f.write(''.join([w + '\n' for w in corpus]))
    
    print("Corpus created, size: %d words." % len(corpus))

    return corpus


def permuted_dictionary_attack_pool_kernel(hash:str, h:str, suffixes:list, corpus:list,
                                           quit, foundit, q):
    """
    Attempts to crack the password using a permuted dictionary attack.
    """
    for w in tqdm.tqdm(corpus):
        if quit.is_set():
            return False
        for w in permute(w, suffixes):
            if h((w).encode('utf-8')).hexdigest() == hash:
                foundit.set()
                q.put(w)
                return   
    return


def permuted_dictionary_attack_pool(hash:str,hash_type:str,upgrade=True, n_threads:int=100):
    """
    Attempts to crack the password using a permuted dictionary attack.
    This is optimised to run on multiple CPU cores.
    """
    # Get hash function
    h = HASH_TYPES.get(hash_type)
    if not h: return False

    # Initialise key variables
    suffixes = gen_suffixes(3, 1)
    corpus = create_english_corpus()
    n_threads = n_threads if n_threads < mp.cpu_count() else mp.cpu_count()
    print("Running on %d cores..." % n_threads)
    if n_threads >= 32 and upgrade: 
        print("Upgrading settings for high performance machine...")
        suffixes = gen_suffixes(4, 1)
    elif n_threads >= 64 and upgrade:
        print("Upgrading settings for high performance machine...")
        suffixes = gen_suffixes(5, 2)
    n_blocks = len(suffixes) // n_threads + 1

    # Sort out suffixes and blocks them for each core
    suffixes = suffixes + ['' for i in range(n_blocks * n_threads - len(suffixes))]
    suffixes = np.asarray(suffixes).reshape((n_threads, n_blocks))
    
    # Here for ensuring that program quits early if password is found
    q = mp.Queue()
    quit = mp.Event()
    foundit = mp.Event()

    # Start cores
    for i in range(n_threads):
        p = mp.Process(target=permuted_dictionary_attack_pool_kernel, args=(hash, h, suffixes[i], corpus, quit, foundit, q))
        p.start()
        time.sleep(0.75)

    # Get answer
    foundit.wait()
    quit.set()
    
    return q.get() if not q.empty() else False


def brute_force_attack_light(hash:str,hash_type:str, upto:int=4):
        
    # Get hash function
    h = HASH_TYPES.get(hash_type)
    if not h: return False
    
    total_number_passwords = sum([math.factorial(len(CHARACTERS)) / math.factorial(len(CHARACTERS) - (upto - i)) for i in range(upto)])

    for i in range(upto+1):
        print('Starting brute force attack with %d CHARACTERS...' % i)
        for w in tqdm.tqdm(permutations(CHARACTERS, i), total=total_number_passwords): 
            w = ''.join(w)
            if h(w.encode('utf-8')).hexdigest() == hash:
                    return w
    
    return False


def brute_force_attack_heavy(hash:str,hash_type:str, upto:int=4):
        
    # Get hash function
    h = HASH_TYPES.get(hash_type)
    if not h: return False
    
    total_number_passwords = sum([math.factorial(len(CHARACTERS)) / math.factorial(len(CHARACTERS) - (upto - i)) for i in range(upto)])

    for i in range(upto+1):
        print('Starting brute force attack with %d CHARACTERS...' % i)
        for w in tqdm.tqdm(permutations(CHARACTERS, i), total=total_number_passwords): 
            w = ''.join(w)
            if h(w.encode('utf-8')).hexdigest() == hash:
                    return w
    
    return False



def next_permutation(COUNTER:int)->str:

    w = ''

    if COUNTER == 0:
        return CHARACTERS[0]
    elif COUNTER == len(CHARACTERS):
        return CHARACTERS[0] + CHARACTERS[0]
    
    log = int(math.floor(math.log(COUNTER, len(CHARACTERS)))) 
    l_prep = COUNTER - len(CHARACTERS)**(log-1)
    length = int(math.floor(math.log(l_prep, len(CHARACTERS)))) 

    new_character_index = COUNTER % len(CHARACTERS)
    old_character_index = (COUNTER // len(CHARACTERS) - 1)

    for i in range(length):
        w = CHARACTERS[old_character_index % len(CHARACTERS)] + w
        old_character_index = old_character_index // len(CHARACTERS) - 1
        
    w += CHARACTERS[new_character_index]
    COUNTER += 1
    return w


def brute_force_kernel(hash:str, h:str, upto:int, num_threads:int, pid:int, quit, foundit, q):

    for i in tqdm.tqdm(range(pid,upto+1, num_threads)):
        w = next_permutation(i)
        if quit.is_set():
            return False
        w = ''.join(w)
        if h(w.encode('utf-8')).hexdigest() == hash:
            q.put(w)
            foundit.set()
            return
    return


def brute_force_attack_pool(hash:str,hash_type:str, upto:int=4, n_threads:int=100):
    # Get hash function
    h = HASH_TYPES.get(hash_type)
    if not h: return False

    # Initialise key variables
    n_threads = n_threads if n_threads < mp.cpu_count() else mp.cpu_count()
    total_number_passwords = int(sum([math.factorial(len(CHARACTERS)) / math.factorial(len(CHARACTERS) - (upto - i)) for i in range(upto)]))

    # Here for ensuring that program quits early if password is found
    q = mp.Queue()
    quit = mp.Event()
    foundit = mp.Event()

    # Start cores
    for i in range(n_threads):
        p = mp.Process(target=brute_force_kernel, args=(hash, h, total_number_passwords,
                                                         n_threads, i,
                                                         quit, foundit, q))
        p.start()
        time.sleep(0.5)

    # Get answer
    foundit.wait()
    quit.set()
    
    return q.get() if not q.empty() else False


def pwd_crack(hash:str)->bool:
    """
    Attempts to crack the hash to get the password.
    """
    hash_type = get_hash_type(hash)
    if not hash_type:
        return False

    # Brute Force attack
    brute = brute_force_attack_light(hash, hash_type, 4)
    if brute:
        print(Style.BRIGHT + Fore.GREEN + "Light Brute Force Attack Successful. Password is: %s" % perms)
        return brute
    print(Style.BRIGHT + Fore.RED + "Light Brute Force Attack Failed. Could not crack password. :(")


    # Attempt to bust hash
    busted = search_hash_online(hash)
    if busted:
        print(Style.BRIGHT + Fore.GREEN + "Online Hash Busting Successful. Password is: %s" % busted)
        return busted
    print(Style.BRIGHT + Fore.RED + "Hash not found in online database. Attempting dictionary attack...")


    # Dictionary attack
    dictionary = dictionary_attack(hash, hash_type)
    if dictionary:
        print(Style.BRIGHT + Fore.GREEN + "Dictionary Attack Successful. Password is: %s" % dictionary)
        return dictionary
    print(Style.BRIGHT + Fore.RED + "Dictionary Attack Failed. Attempting a permuted dictionary attack...")


    # Permuted dictionary attack
    perms = permuted_dictionary_attack_pool(hash, hash_type)
    if perms:
        print(Style.BRIGHT + Fore.GREEN + "Permuted Dictionary Attack Successful. Password is: %s" % perms)
        return perms
    print(Style.BRIGHT + Fore.RED + "Permuted Dictionary Attack Failed. Attempting a brute force attack...")


    # Brute Force attack
    brute = brute_force_attack_heavy(hash, hash_type, 5)
    if brute:
        print(Style.BRIGHT + Fore.GREEN + "Heavy Brute Force Attack Successful. Password is: %s" % perms)
        return brute
    print(Style.BRIGHT + Fore.RED + "Heavy Brute Force Attack Failed. Could not crack password. :(")

    return False

if __name__ == '__main__':
    hash = to_hash('asdf', 'md5')
    print(brute_force_attack_pool(hash, 'md5', 5))
