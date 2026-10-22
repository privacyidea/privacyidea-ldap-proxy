# Publishing Python releases

The `Python distributions` workflow in `.github/workflows/python-dist.yml` builds a
wheel and source distribution on branch pushes, pull requests to `master`, and
`v*` tag pushes. Tags containing `dev` are excluded. It checks the package
description, required proxy modules, and twistd plugin before storing both files
as the `python-dist` artifact.

Only a `v*` tag push in `privacyidea/privacyidea-ldap-proxy` can run the separate
PyPI publishing job. That job downloads the checked artifact without checking out
or building source code. It uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
with the `pypi` environment and `id-token: write`; no stored PyPI API token is needed.
All actions are pinned to full commit SHAs.

## Maintainer setup

Before the first upload:

1. A PyPI project owner must review existing publishers and
   [register a GitHub Actions publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
   for the existing `pi-ldapproxy` project with these values:

   | Field | Value |
   | --- | --- |
   | Repository owner | `privacyidea` |
   | Repository name | `privacyidea-ldap-proxy` |
   | Workflow filename | `python-dist.yml` |
   | Environment name | `pypi` |

2. A repository administrator should configure the GitHub `pypi` environment,
   restrict deployments to release tags, and add required reviewers if appropriate.
   See [GitHub environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment).
3. Confirm whether another release process already uploads to PyPI and coordinate
   the switch so that only one process publishes each distribution file.

## Creating a release

1. Update `version` in `setup.py` and the changelog for the intended release.
   The GitHub release `v0.8` currently exists, but `setup.py` still declares `0.7`;
   resolve that discrepancy before creating the next release.
2. Merge the version update and this workflow before creating the release tag.
   Maintenance branches also need the workflow before their next release tag.
3. Push a new `v<version>` tag pointing to the release commit. The distribution
   check requires the tag to match the version embedded in both package artifacts.
4. Review the build results and approve the `pypi` deployment if required by the
   environment. The publishing action uploads the same checked files and creates
   attestations using the workflow's Trusted Publisher identity.

Merging this workflow or publishing a GitHub release for an existing tag does not
upload a package. Existing tags are not republished automatically; do not move a
published release tag just to trigger the workflow.

The workflow does not ignore existing files. PyPI does not allow
[filename reuse](https://pypi.org/help/#file-name-reuse). If an upload partially
succeeds, inspect the files on PyPI before deciding how to finish the release.
End-to-end publication requires the maintainer setup above and a new release tag.
