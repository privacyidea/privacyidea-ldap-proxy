import os
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


REQUIRED_FILES = {
    'pi_ldapproxy/__init__.py',
    'pi_ldapproxy/config.py',
    'pi_ldapproxy/proxy.py',
    'twisted/plugins/ldapproxy_plugin.py',
}


def check_metadata(data):
    metadata = BytesParser().parsebytes(data)
    if metadata['Name'] != 'pi-ldapproxy' or not metadata['Version']:
        raise SystemExit('Unexpected distribution name or missing version')
    if metadata['Description-Content-Type'] != 'text/markdown':
        raise SystemExit('The distribution must declare its Markdown description')
    ref = os.environ.get('GITHUB_REF', '')
    if ref.startswith('refs/tags/') and ref != 'refs/tags/v' + metadata['Version']:
        raise SystemExit('Release tag does not match package version ' + metadata['Version'])
    return metadata['Version']


def main():
    wheels = list(Path('dist').glob('*.whl'))
    sdists = list(Path('dist').glob('*.tar.gz'))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit('Expected exactly one wheel and one source distribution')

    with zipfile.ZipFile(wheels[0]) as wheel:
        paths = set(wheel.namelist())
        if not REQUIRED_FILES <= paths:
            raise SystemExit('Wheel is missing proxy modules or the twistd plugin')
        metadata_paths = [p for p in paths if p.endswith('.dist-info/METADATA')]
        if len(metadata_paths) != 1:
            raise SystemExit('Expected exactly one wheel metadata file')
        wheel_version = check_metadata(wheel.read(metadata_paths[0]))

    with tarfile.open(sdists[0]) as sdist:
        names = sdist.getnames()
        roots = {p.split('/')[0] for p in names}
        if len(roots) != 1:
            raise SystemExit('Expected one source distribution root directory')
        root = roots.pop()
        if not REQUIRED_FILES <= {p.partition('/')[2] for p in names}:
            raise SystemExit('Source distribution is missing proxy modules or the twistd plugin')
        sdist_version = check_metadata(sdist.extractfile(root + '/PKG-INFO').read())

    if wheel_version != sdist_version:
        raise SystemExit('Wheel and source distribution versions differ')
    print('Checked pi-ldapproxy ' + wheel_version + ': wheel, source distribution and release tag')


if __name__ == '__main__':
    main()
