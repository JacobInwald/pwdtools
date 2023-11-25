from passwordmeter import test
from urllib.request import urlopen
from os.path import isfile
from random import choice,randint
import re

def pwd_strength(pwd:str)->str:
    """
    Return the strength of a password.
    """
    strengths = {0: 'very weak', 1: 'weak', 2: 'not great', 3: 'strong', 4: 'very strong'}
    vw_grade = {'name': 0, 'minlength': 1, 'specialcharacterrange': 0, 'uppercaserange': 0, 'numberrange': 0}
    w_grade = {'name': 1, 'minlength': 5, 'specialcharacterrange': 0, 'uppercaserange': 1, 'numberrange': 0}
    m_grade = {'name': 2, 'minlength': 7, 'specialcharacterrange': 0, 'uppercaserange': 1, 'numberrange': 1}
    s_grade = {'name': 3, 'minlength': 9, 'specialcharacterrange': 1, 'uppercaserange': 2, 'numberrange': 2}
    vs_grade = {'name': 4, 'minlength': 12, 'specialcharacterrange': 2, 'uppercaserange': 2, 'numberrange': 3}
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
