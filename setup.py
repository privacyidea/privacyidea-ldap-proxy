from distutils.core import setup

setup(name='pi-ldapproxy',
      version='0.2',
      description='privacyIDEA LDAP Proxy based on Twisted',
      packages=['pi_ldapproxy', 'pi_ldapproxy.test', 'twisted.plugins'],
      )
