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
