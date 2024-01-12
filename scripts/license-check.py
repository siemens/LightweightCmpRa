#!/usr/bin/python3
"""Tools to parse and process a software bill of materials (SBOM) in CycloneDX format, to check whether all the
dependencies used in the project use compatible licenses."""

import json
import logging
import sys
import argparse
import pathlib

# This is a set of special licenses that we treat in a unique way. They are not, and will not be featured in the SPDX,
# because they are just an alias for another license (see referenced discussions for context). Therefore, we explicitly
# give their names here (since they don't have IDs).
SPECIAL_LICENSES = {
    'Bouncy Castle Licence',  # https://github.com/spdx/license-list-XML/issues/910, MIT
    'Eclipse Distribution License - Version 1.0',  # https://github.com/spdx/license-list-XML/issues/1683, BSD-3-clause
}


def discover_licenses(sbom):
    """Return a set of licenses featured in a given SBOM

    :param sbom: dict, loaded SBOM data from a JSON file
    :returns: set of strings that correspond to licenses featured in the SBOM"""
    found_licenses = set()
    for item in sbom['components']:
        name, version, licenses = item['name'], item['version'], item['licenses']
        # logging.debug(f'Processing {name}')
        if not item['licenses']:
            logging.warning(f'{name} {version}: Unspecified license!')

        for entry in licenses:
            if 'expression' in entry:
                # Special case for clever licenses that are given as boolean expressions, e.g.
                # "(CDDL-1.0 OR GPL-2.0-with-classpath-exception)". If this happens, we add the entire expression
                # to the list without trying to parse it (because the notation can be complex). The entire expression
                # must be added to the list of allowed licenses after a human checks it and ensures all is well.
                # Yes, there will be different strings that have the same meaning (e.g. "X or Y", "Y or X") and they
                # will have to be treated as different cases - that's fine. A human will have to think about it very
                # well before updating allowed-licenses.txt.
                found_licenses.add(entry['expression'])

            elif 'id' not in entry['license'] and entry['license']['name'] in SPECIAL_LICENSES:
                # Some licenses do not have an SPDX ID, this occurs when these licenses are nothing but renamed copies
                # of some other license. In this case we extract the license name.
                found_licenses.add(entry['license']['name'])

            else:
                found_licenses.add(entry['license']['id'])
    return found_licenses


def generate_license_report(sbom):
    """Generate a list of licenses from the given SBOM

    :param sbom: dict, loaded SBOM data from a JSON file
    :returns: list of tuples(name, version, license), each tuple element is a string"""
    entries = []
    for item in sbom['components']:
        name, version, licenses = item['name'], item['version'], item['licenses']
        if not item['licenses']:
            entries.append((name, version, None))

        for entry in licenses:
            # according to the JSON schema of components/licenses/license, either `id` or `name` must be there
            try:
                license_id = entry['license']['id']
            except KeyError:
                try:
                    license_id = entry['license']['name']
                except KeyError:
                    license_id = entry['expression']
            entries.append((name, version, license_id))
    return entries


def pretty_report(licenses):
    """Stringify the license list of the SBOM as an ASCII table

    :param licenses: list of tuples(name, version, license), each tuple element is a string
    :returns: str, tabular representation of the data
    """
    result = 'Component           \tVersion \tLicense\n'
    for name, version, license in licenses:
        result += f'{name: <20}\t{version: <8}\t{license}\n'
    return result


def check_license_compliance(sbom, allowed):
    """Verify if the licenses in the SBOM correspond to the ones allowed in the project

    :param sbom: dict, loaded SBOM data from a JSON file
    :param allowed: set of str, containing allowed licenses
    :returns: bool, True if everything is compliant, otherwise False; violations will be logged"""
    errors = []  # list of tuples, each entry is (component name, version, error type)
    for item in sbom['components']:
        name, version, licenses = item['name'], item['version'], item['licenses']
        if not item['licenses']:
            errors.append((name, version, 'no license specified'))

        for license in licenses:
            # according to the JSON schema of components/licenses/license, either `id` or `name` must be there
            try:
                license_id = license['license']['id']
            except KeyError:
                try:
                    license_id = license['license']['name']
                except KeyError:
                    license_id = license['expression']
            if license_id in allowed:
                break
            else:
                errors.append((name, version, f'`{license_id}` not allowed'))

    if not errors:
        return True

    logging.warning('License issues found: %i', len(errors))
    for error in errors:
        logging.warning(error)
    return False


def load_allowed_licenses(path):
    result = set()
    with open(path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            result.add(line.strip())
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)7s  %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--sbom", help="Path to SBOM JSON file", type=str, required=True)
    parser.add_argument("--enforce", help="Path to list of allowed licenses", type=pathlib.Path)
    parser.add_argument('--report', help="Print a report of components and licenses", action='store_true')
    args = parser.parse_args()

    raw_sbom = open(args.sbom, 'r').read()
    parsed_sbom = json.loads(raw_sbom)

    discovery = discover_licenses(parsed_sbom)
    logging.info('Licenses discovered: %s', discovery)

    if args.report:
        summary = pretty_report(generate_license_report(parsed_sbom))
        logging.info('Producing license report: \n%s', summary)

    if args.enforce:
        allowed = load_allowed_licenses(args.enforce)
        valid = check_license_compliance(parsed_sbom, allowed)
        if valid:
            logging.info('SUCCESS: No license issues found')
            sys.exit(0)

        sys.exit(1)