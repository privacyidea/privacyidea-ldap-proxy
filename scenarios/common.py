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