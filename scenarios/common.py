import ldap3

def construct_dn(username, base_dn, uid_attribute):
    """
    Given username, base DN and the uid attribute (probably "cn"), construct the user's DN.
    :param username: supplied username
    :param base_dn: configured LDAP base DN
    :param uid_attribute: name of the RDN attribute against which we should match the username
    :return:
    """
    return '{attr}={username},{base_dn}'.format(
        username=username,
        base_dn=base_dn,
        attr=uid_attribute
    )


def lookup_user(username,ldap_server, service_account_dn, service_account_password,
                base_dn, loginname_attribute, filter_template='({attr}={username})'):
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
        print('[Service Account] Successful bind!')
        conn.search(base_dn,
                    filter_template.format(attr=loginname_attribute, username=username),
                    attributes=['cn'])
        print('[Service Account] Looking for entry that satisfies {attr}={username}'.format(
            attr=loginname_attribute,
            username=username))
        if len(conn.entries) != 1:
            raise RuntimeError('Expected one entry, found {}!'.format(len(conn.entries)))
        entry = conn.entries[0]
        return entry.entry_dn
    else:
        raise RuntimeError('[Service Account] Bind FAILED!')