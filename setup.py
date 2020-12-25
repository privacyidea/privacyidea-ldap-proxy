import sys
from setuptools import setup

def get_file_contents(file_path):
    """Get the context of the file using full path name."""
    content = ""
    try:
        full_path = os.path.join(package_directory, file_path)
        content = open(full_path, 'r').read()
    except:
        print("### could not open file {0!r}".format(file_path), file=sys.stderr)
    return content

setup(name='pi-ldapproxy',
      version='0.6',
      description='privacyIDEA LDAP Proxy based on Twisted',
      packages=['pi_ldapproxy', 'pi_ldapproxy.test', 'twisted.plugins'],
      author='privacyidea.org',
      license='AGPLv3',
      url='http://www.privacyidea.org',
      long_description=get_file_contents('README.md')
      )
