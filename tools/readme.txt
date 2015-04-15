beanstalkc.py:
 It is a modified version of beanstalkc supporting authentication.
 It has a new method called 'authenticate(cfg)' where config could have one of
 the following structures

    1) {'username': 'xx', 'password': 'mmmm'}
    2) {'username': 'xx', 'pw_hash': '3cec4db24e0b6b8313084b8c4213588b"} where pw_hash = md5sum(username::password)
    3) {'auth_file: '/etc/beanstalkc.cred'}  where 'cat /etc/beanstalkc.cred' = xx::3cec4db24e0b6b8313084b8c4213588b

This method must be explicitly called by the user of the Connection class.

You can use bs_user to create the password file for client or server
    ./bs_user.sh <user> <password> > <file>

You can also use htdigest to create the password file.
    htdigest -c filename '' username
