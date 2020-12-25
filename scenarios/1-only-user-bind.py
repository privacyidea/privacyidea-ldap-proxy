"""
Scenario 1) Web Application has no service account, performs only user bind, no search.

Given a user's login name, the web application can automatically determine the corresponding DN
(without having to ask the LDAP server). The web application does not query the LDAP server
for any information about the user.
"""
import configobj
import ldap3
from common import construct_dn

def login(username, password, ldap_server, base_dn, uid_attribute):
    """
    Given username, password and a LDAP configuration, attempt a login.
    :param username: login name of the user
    :param password: supplied password
    :param ldap_server: LDAP server IP
    :param base_dn: see `construct_dn`
    :param uid_attribute: see `construct_dn`
    :return: boolean
    """
    dn = construct_dn(username, base_dn, uid_attribute)
    print('Given username {!r}, constructed dn: {!r}'.format(username, dn))
    print('Connecting to LDAP server {!r} ...'.format(ldap_server))
    conn = ldap3.Connection(ldap_server, user=dn, password=password)
    print('Bind with password {!r} ...'.format(password), end=' ')
    result = conn.bind()
    if result:
        print('Successful bind!')
    else:
        print('Bind FAILED!')
    return result

if __name__ == '__main__':
    with open('config.ini') as f:
        config = configobj.ConfigObj(f)
    password = config['password']
    if not password:
        password = input('Password? ')
    login(config['username'],
          password,
          config['ldap-server'],
          config['base-dn'],
          config['uid-attribute'])
