# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import os
from setuptools import setup

package_directory = os.path.dirname(os.path.abspath(__file__))


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
      install_requires=['ldaptor',
                        'six',
                        'future',
                        'Twisted',
                        'configobj',
                        'pyOpenSSL',
                        'service-identity'],
      long_description=get_file_contents('README.md')
      )
