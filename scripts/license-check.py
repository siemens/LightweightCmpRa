#!/usr/bin/python3
"""Tools to parse and process a software bill of materials (SBOM) in CycloneDX format, to check whether all the
dependencies used in the project use compatible licenses."""

import json
import logging
import sys
import argparse
import pathlib


def discover_licenses(sbom):
    """Return a set of licenses featured in a given SBOM

    :param sbom: dict, loaded SBOM data from a JSON file
    :returns: set of strings that correspond to licenses featured in the SBOM"""
    found_licenses = set()
    for item in sbom['components']:
        name, version, licenses = item['name'], item['version'], item['licenses']
        if not item['licenses']:
            logging.warning(f'{name} {version}: Unspecified license!')

        for entry in licenses:
            # special treatment for bouncy castle
            # https://github.com/spdx/license-list-XML/issues/910
            if 'id' not in entry['license'] and entry['license']['name'] == 'Bouncy Castle Licence':
                found_licenses.add('Bouncy Castle Licence')
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
                license_id = entry['license']['name']
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
                license_id = license['license']['name']
            if license_id not in allowed:
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