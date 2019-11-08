import pwd, grp, os, crypt

USERS = [
    ['666666', '666666'],
    ['888888', '888888'],
    ['admin','password'],
    ['admin1','password'],
    ['administrator', '1234'],
    ['Administrator', 'admin'],
    ['guest', '12345'],
    ['mother', 'fucker'],
    ['root', '7ujMko0vizxv'],
    ['service', 'service'],
    ['supervisor', 'supervisor'],
    ['support', 'support'],
    ['tech', 'tech'],
    ['ubnt', 'ubnt'],
    ['user', 'user']
]

def user_exists(username):
    try:
        pwd.getpwnam(username)
        return 1
    except KeyError:
        print('User ' + username + ' does not exist.')
        return 0

def group_exists(groupname):
    try:
        grp.getgrnam(groupname)
        return 1
    except KeyError:
        print('Group ' + groupname + ' does not exist.')
        return 0

def add_user(username,password):
    password_encrypted = crypt.crypt(password, "123")
    if group_exists(username):
        os.system("useradd -m -p " + password_encrypted + " -g " + username + ' ' + username)
    else:
        os.system("useradd -m -p " + password_encrypted + " " + username)

def set_password(username,password):
    password_encrypted = crypt.crypt(password, "123")
    os.system("usermod -p " + password_encrypted + " " + username)

if __name__ == '__main__':
    for user in USERS:
        if user_exists(user[0]):
            set_password(user[0],user[1])
        else:
            add_user(user[0], user[1])