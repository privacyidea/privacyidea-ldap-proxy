from setuptools import setup

setup(name='pi-ldapproxy',
      version='0.6',
      description='privacyIDEA LDAP Proxy based on Twisted',
      packages=['pi_ldapproxy', 'pi_ldapproxy.test', 'twisted.plugins'],
      author='privacyidea.org',
      license='AGPLv3',
      url='http://www.privacyidea.org',
      long_description=get_file_contents('README.md')
      )
