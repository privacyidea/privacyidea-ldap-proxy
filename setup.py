from distutils.core import setup

setup(name='pi-ldapproxy',
      version='0.1',
      description='privacyIDEA LDAP Proxy based on Twisted',
      author='privacyidea.org',
      packages=['pi_ldapproxy', 'pi_ldapproxy.test', 'twisted.plugins'],
      )
