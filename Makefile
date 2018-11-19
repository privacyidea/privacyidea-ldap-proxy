info:
	@echo "make clean        - remove all automatically created files"
	@echo "make debianzie    - prepare the debian build environment in DEBUILD"
	@echo "make builddeb     - build .deb file locally on ubuntu 14.04LTS!"
	
#VERSION=1.3~dev5
SHORT_VERSION=0.6
#SHORT_VERSION=2.10~dev7
VERSION_JESSIE=${SHORT_VERSION}
VERSION=${SHORT_VERSION}
LOCAL_SERIES=`lsb_release -a | grep Codename | cut -f2`
BUILDENV_DIR=buildenv
SRCDIRS=deploy pi_ldapproxy tools twisted ${BUILDENV_DIR}
SRCFILES=setup.py MANIFEST.in Makefile Changelog LICENSE  requirements.txt example-proxy.ini README.md 

INSTALL_DIR=\/opt\/privacyidea-ldap-proxy

clean:
	find . -name \*.pyc -exec rm {} \;
	rm -fr build/
	rm -fr dist/
	rm -fr DEBUILD
	rm -fr RHBUILD
	rm -fr cover
	rm -f .coverage

createvenv:
	rm -fr ${BUILDENV_DIR}
	virtualenv ${BUILDENV_DIR}
	(. buildenv/bin/activate; pip install -r requirements.txt)
	(. buildenv/bin/activate; pip install .)
	virtualenv --relocatable ${BUILDENV_DIR}
	sed -e s/'^VIRTUAL_ENV=.*'/'VIRTUAL_ENV=${INSTALL_DIR}'/ buildenv/bin/activate > activate.tmp
	mv activate.tmp buildenv/bin/activate

debianize:
	make clean
	make createvenv
	mkdir -p DEBUILD/privacyidea-ldap-proxy.org/debian
	cp -r ${SRCDIRS} ${SRCFILES} DEBUILD/privacyidea-ldap-proxy.org || true
	cp LICENSE DEBUILD/privacyidea-ldap-proxy.org/debian/copyright
	cp LICENSE DEBUILD/privacyidea-ldap-proxy.org/debian/python-privacyidea.copyright
	cp LICENSE DEBUILD/privacyidea-ldap-proxy.org/debian/privacyidea-all.copyright
	(cd DEBUILD; tar -zcf privacyidea-ldap-proxy_${SHORT_VERSION}.orig.tar.gz --exclude=privacyidea-ldap-proxy.org/debian privacyidea-ldap-proxy.org)

builddeb:
	make debianize
	################## Renew the changelog
	cp -r deploy/debian-ubuntu/* DEBUILD/privacyidea-ldap-proxy.org/debian/
	################# Build
	(cd DEBUILD/privacyidea-ldap-proxy.org; debuild --no-lintian)

pypi:
	python setup.py sdist upload

