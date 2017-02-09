"""
Scenario 3) App uses a service account to look up user's DN and uses user search after bind.

Given a username, the app uses a service account to find the user's DN. For that, it performs an LDAP bind followed
by an LDAP server. After that, it issues a bind on behalf of the user and uses an LDAP search under the user's
context to retrieve profile information of the user.
"""
from pprint import pprint

import ldap3
import configobj

def lookup_user(username, ldap_server, service_account_dn, service_account_password, base_dn, loginname_attribute):
    """
    Given an user-provided username, lookup the user's DN. If the user couldn't be found, raise a RuntimeError.
    :param username: login name
    :param ldap_server: LDAP server IP
    :param service_account_dn: DN of the service account
    :param service_account_password: Password of the service account
    :param base_dn: DN under which users are located
    :param loginname_attribute: Attribute which should match *username*
    :return: User's DN as a string
    """
    conn = ldap3.Connection(ldap_server, user=service_account_dn, password=service_account_password)
    result = conn.bind()
    if result:
        print '[Service Account] Successful bind!'
        conn.search(base_dn,
                    '({attr}={username})'.format(attr=loginname_attribute, username=username),
                    attributes=['cn'])
        print '[Service Account] Looking for entry that satisfies {attr}={username}'.format(
            attr=loginname_attribute,
            username=username)
        if len(conn.entries) != 1:
            raise RuntimeError('Expected one entry, found {}!'.format(len(conn.entries)))
        entry = conn.entries[0]
        return entry.entry_dn
    else:
        raise RuntimeError('[Service Account] Bind FAILED!')


def login(username, password, ldap_server, service_account_dn, service_account_password, base_dn, loginname_attribute):
    """
    Given username, password and a LDAP configuration, attempt a login.
    :param username: login name of the user
    :param password: supplied password
    :param ldap_server: LDAP server IP
    :param service_account_dn: Distinguished Name of the service account
    :param service_account_password: Password of the service account
    :param base_dn: the base DN under which user search should be performed
    :param loginname_attribute: the attribute which contains the login name
    :return: dictionary with boolean key 'success'. In case of success, it also contains user information.
    """
    dn = lookup_user(username, ldap_server, service_account_dn, service_account_password, base_dn, loginname_attribute)
    print 'Given username {!r}, looked up dn: {!r}'.format(username, dn)
    print 'Connecting to LDAP server {!r} ...'.format(ldap_server)
    conn = ldap3.Connection(ldap_server, user=dn, password=password)
    print 'Bind with password {!r} ...'.format(password),
    result = conn.bind()
    if result:
        print 'Successful bind!'
        # Fetch user information
        conn.search(dn, '(objectClass=*)', attributes=ldap3.ALL_ATTRIBUTES)
        if len(conn.entries) != 1:
            raise RuntimeError('Expected one entry, found {}!'.format(len(conn.entries)))
        entry = conn.entries[0]
        return {
            'success': True,
            'displayName': entry.displayName.value,
        }
    else:
        print 'Bind FAILED!'
        return {
            'success': False,
        }

if __name__ == '__main__':
    with open('config.ini') as f:
        config = configobj.ConfigObj(f)
    password = config['password']
    if not password:
        password = raw_input('Password? ')
    pprint(login(config['username'],
                 password,
                 config['ldap-server'],
                 config['service-account-dn'],
                 config['service-account-password'],
                 config['base-dn'],
                 config['loginname-attribute']))