#!/usr/bin/env python3
#
# A simple tool to query the National Vulnerability Database (NVD) with colors support.
#
# https://github.com/cddmp/cvecheck

from argparse import ArgumentParser
from enum import Enum
import nvdlib
import os
import re

COLORS = True
CVSSV2 = "v2"
CVSSV3 = "v3"

class Ansi(Enum):
    bold = '\033[1m'
    underline = '\033[4m'
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    very_red = '\033[101m'

    def __call__(self, string):
        if COLORS:
            return f'{self.value}{string}\033[0m'
        return string

class ColoredEntry():
    def __init__(self, entry):
        self.entry = entry
        self.id = self._color_id(entry.id)
        self.url = self.entry.url

        self.v2score = None
        self.v30score = None
        self.v31score = None
        if hasattr(entry, 'v2score'):
            self.v2score =  self._color_score(entry.v2score, False)
        if hasattr(entry, 'v30score'):
            self.v30score = self._color_score(entry.v30score)
            self.entry.v3score = self.v30score
        elif hasattr(entry, 'v31score'):
            self.v31score =  self._color_score(entry.v31score)
            self.entry.v3score = self.v31score

        self.v2severity = None
        self.v3severity = None
        if hasattr(entry, 'v2severity'):
            self.v2severity =  self._color_severity(entry.v2severity.capitalize())
        if hasattr(entry, 'v30severity'):
            self.v30severity =  self._color_severity(entry.v30severity.capitalize())
        elif hasattr(entry, 'v31severity'):
            self.v31severity =  self._color_severity(entry.v31severity.capitalize())

        self.v2vector = None
        self.v3vector = None
        if hasattr(entry, 'v2vector'):
            self.v2vector =  f"CVSS:2.0/{entry.v2vector}"
        if hasattr(entry, 'v30vector'):
            self.v30vector =  entry.v30vector
        elif hasattr(entry, 'v31vector'):
            self.v31vector =  entry.v31vector

        self.description = entry.descriptions[0].value.rstrip()

    def __repr__(self):
        result = f"\n{self.id}\n\n"
        if self.v30score:
            result += f"CVSS v3.0 Base Score: {self.v30score} ({self.v30severity}) ({self.v30vector})\n"
        elif self.v31score:
            result += f"CVSS v3.1 Base Score: {self.v31score} ({self.v31severity}) ({self.v31vector})\n"
        if self.v2score:
            result += f"CVSS v2 Base Score: {self.v2score} ({self.v2severity}) ({self.v2vector})\n\n"
        if not self.v30score and not self.v31score and not self.v2score:
            result += f"CVSS v3.1 Base Score: unassigned\n"
            result += f"CVSS v3.0 Base Score: unassigned\n"
            result += f"CVSS v2 Base Score: unassigned\n\n"
        result += f"{self.url}\n\n"
        result += f"{self.description}\n"
        return result

    def _color_id(self, cve_id):
        return Ansi.underline(Ansi.bold(cve_id))
    
    def _color_severity(self, severity):
        mapping = {
                "Low": Ansi.green,
                "Medium": Ansi.yellow,
                "High": Ansi.red,
                "Critical": Ansi.very_red, 
            }
        return mapping[severity](severity)

    def _color_score(self, score, cvss3=True):
        if score == 0.0:
            return str(score)
        if 0.1 <= score <= 3.9:
            return Ansi.green(str(score))
        if 4.0 <= score <= 6.9:
            return Ansi.yellow(str(score))
        if not cvss3:
            if 7.0 <= score <= 10.0:
                return Ansi.red(str(score))
        if 7.0 <= score <= 8.9:
            return Ansi.red(str(score))
        if 9.0 <= score <= 10.0:
            return Ansi.very_red(str(score))

class CvssSeverityFilter():
    def __init__(self, version, severity_filter):
        self.version = version
        self.severity_filter = severity_filter
        self.severities = None
        self.single_filter = False

        if not self._parse_filter(severity_filter):
            raise Exception('invalid severity filter')

    def match( self, entry):
        if self.version == CVSSV3:
            if hasattr(entry, 'v30severity'):
                severity = entry.v30severity
            elif hasattr(entry, 'v31severity'):
                severity = entry.v31severity
            else:
                return False
        elif self.version == CVSSV2:
            if not hasattr(entry, 'v2severity'):
                return False
            severity = entry.v2severity

        if severity == '':
            return False

        if severity.lower() in self.severities:
            return True
        return False

    def _parse_filter(self, severity_filter):
        severity_filter = severity_filter.strip()
        severities = severity_filter.split(',', 4)
        if len(severities) == 1:
            self.single_filter = True

        for severity in severities:
            severity = severity.lower()
            if severity in ['low', 'medium', 'high'] or (self.version == 'v3' and severity == 'critical'):
                self.severities = severities
                continue
            else:
                return False

        return True

class CvssScoreFilter():
    def __init__(self, version, score_filter):
        self.version = version
        self.score_filter = score_filter
        self.min = None
        self.max = None

        if not self._parse_filter(score_filter):
            raise Exception('invalid score filter')

    def match(self, entry):
        if self.version == CVSSV3:
            if hasattr(entry, 'v30score'):
                score = entry.v30score
            elif  hasattr(entry, 'v31score'):
                score = entry.v31score
            else:
                return False
        elif self.version == CVSSV2:
            if not hasattr(entry, 'v2score'):
                return False
            score = entry.v2score

        if score is None:
            return False

        if not self.max:
            if score == self.min:
                return True
        elif score >= self.min and score <= self.max:
            return True

        return False

    def _parse_filter(self, score_filter):
        score_filter = score_filter.strip()
        numbers = score_filter.split('-', 1)
        for count, number in enumerate(numbers):
            if self._valid_float_score(number):
                result = float(number)
            elif self._valid_int_score(number):
                result = int(number)
            else:
                return False

            if count == 0:
                self.min = result
            elif count == 1:
                self.max = result

        return True

    def _valid_float_score(self, x):
        try:
            result = float(x)
            if 0.0 < result > 10.0:
                return False
        except (TypeError, ValueError):
            return False
        return True

    def _valid_int_score(self, x):
        try:
            result = int(x)
            if 0 < result > 10:
                return False
        except (TypeError, ValueError):
            return False
        return True

def print_banner():
    print(Ansi.bold(Ansi.green('-= CVECHECK =-')), end='\n\n')

def print_info(msg):
    print(Ansi.bold(f'[*] {msg}'))

def parse_arguments():
    parser = ArgumentParser(description="""A simple tool to query the National Vulnerability Database (NVD) with colors support.""")
    parser.add_argument('search', help=f'search by keyword (e.g.,"{Ansi.bold("OpenSSL 1.0.2f")}"), CVE (e.g.,"{Ansi.bold("CVE-2014-0160")}") or CPE (e.g.,"{Ansi.bold("cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*")}")')

    mode_switch = parser.add_mutually_exclusive_group()
    mode_switch.add_argument('--cve', action="store_true", help=f'enforce CVE search')
    mode_switch.add_argument('--cpe', action="store_true", help=f'enforce CPE search')
    mode_switch.add_argument('--keyword', action="store_true", help=f'enforce keyword search')
    parser.add_argument('--exact-match', dest='exact_match', action='store_true', help=f'return only results which literally match the keyword')

    parser.add_argument('--limit', dest='limit', type=int, help=f'limit the number of results at API level')

    parser_metrics = parser.add_mutually_exclusive_group()
    parser_metrics.add_argument('--filter-v2metrics', dest='v2metrics', help=f'filter by CVSS v2 metrics (e.g.,"{Ansi.bold("I:P")}")')
    parser_metrics.add_argument('--filter-v3metrics', dest='v3metrics', help=f'filter by CVSS v3 metrics (e.g.,"{Ansi.bold("AV:N")}")')

    parser_score = parser.add_mutually_exclusive_group()
    parser_score.add_argument('--filter-v2score', dest='v2score', help=f'filter by CVSS v2 score (e.g.,"{Ansi.bold("3.7-5.0")}" or only "{Ansi.bold("3.7")}")')
    parser_score.add_argument('--filter-v3score', dest='v3score', help=f'filter by CVSS v3 score (e.g.,"{Ansi.bold("3.7-5.0")}" or only "{Ansi.bold("3.7")}")')

    parser_severity = parser.add_mutually_exclusive_group()
    parser_severity.add_argument('--filter-v2severity', dest='v2severity', help=f'filter by CVSS v2 severity (e.g.,"{Ansi.bold("medium,high")}" or only "{Ansi.bold("high")}")')
    parser_severity.add_argument('--filter-v3severity', dest='v3severity', help=f'filter by CVSS v3 severity (e.g.,"{Ansi.bold("medium,high")}" or only "{Ansi.bold("high")}")')
    parser_severity.add_argument('--filter-cweid', dest='cwe_id', help=f'filter by CWE ID (e.g., "{Ansi.bold("CWE-125")}")')
    parser.add_argument('--api-key', dest='api_key', default='', help=f'API key for National Vulnerabilities Database (NVD) for faster queries (optional)')
    args = parser.parse_args()

    if not args.cve and not args.cpe and not args.keyword:
        if args.search.lower().startswith('cpe:'):
            args.cpe = True
            args.cve = False
            args.keyword = False

            # NVD API does not like upper case 'CPE:...'
            args.search = args.search.lower()
        elif args.search.lower().startswith('cve-'):
            args.cpe = False
            args.cve = True
            args.keyword = False

            # NVD API does not like lower case 'cve-...'
            args.search = args.search.upper()
        else:
            args.cpe = False
            args.cve = False
            args.keyword = True

    if (args.cpe or args.cve) and args.exact_match:
        parser.error('--exact-match requires keyword search')

    if args.cwe_id and not re.search(r'^cwe-[0-9]*$', args.cwe_id, re.IGNORECASE):
        parser.error('invalid CWE ID')

    try:
        args.severity_filter = None
        if args.v3severity:
            args.severity_filter = CvssSeverityFilter(CVSSV3, args.v3severity)
        elif args.v2severity:
            args.severity_filter = CvssSeverityFilter(CVSSV2, args.v2severity)

        args.score_filter = None
        if args.v3score:
            args.score_filter = CvssScoreFilter(CVSSV3, args.v3score)
        elif args.v2score:
            args.score_filter = CvssScoreFilter(CVSSV2, args.v2score)
    except Exception as e:
        parser.error(str(e))

    return args

def main():
    global COLORS
    if "NO_COLOR" in os.environ:
        COLORS = False

    print_banner()
    args = parse_arguments()

    entries_v2 = []
    entries_v3 = []
    entries_unrated = []

    cvssV2Severity = False
    cvssV3Severity = False
    if args.severity_filter and args.severity_filter.single_filter:
        if args.severity_filter.version == CVSSV2:
            cvssV2Severity=args.severity_filter.severities[0]
        elif args.severity_filter.version == CVSSV3:
            cvssV3Severity=args.severity_filter.severities[0]

    if args.cve:
        print_info(f'Searching by CVE...')
        cves = nvdlib.searchCVE(cveId=args.search,
                                limit=args.limit,
                                key=args.api_key)
    elif args.keyword:
        print_info(f'Searching by keyword...')
        cves = nvdlib.searchCVE(keywordSearch=args.search,
                                cvssV2Metrics=args.v2metrics,
                                cvssV3Metrics=args.v3metrics,
                                cvssV2Severity=cvssV2Severity,
                                cvssV3Severity=cvssV3Severity,
                                cweId=args.cwe_id,
                                keywordExactMatch=args.exact_match,
                                limit=args.limit,
                                key=args.api_key)
    elif args.cpe:
        print_info(f'Searching by CPE...')
        cves = nvdlib.searchCVE(cpeName=args.search,
                                cvssV2Metrics=args.v2metrics,
                                cvssV3Metrics=args.v3metrics,
                                cvssV2Severity=cvssV2Severity,
                                cvssV3Severity=cvssV3Severity,
                                cweId=args.cwe_id,
                                keywordExactMatch=args.exact_match,
                                limit=args.limit,
                                key=args.api_key)

    for entry in cves:

        if args.severity_filter and not args.severity_filter.match(entry):
            continue
        if args.score_filter and not args.score_filter.match(entry):
            continue

        colored_entry = ColoredEntry(entry)
        if not colored_entry.v30score and not colored_entry.v31score and not colored_entry.v2score:
            entries_unrated.append(colored_entry)
        elif not colored_entry.v30score and not colored_entry.v31score:
            entries_v2.append(colored_entry)
        else:
            entries_v3.append(colored_entry)

    # Sort entries by score in reverse order
    entries_v2 = sorted(entries_v2, key=lambda x: x.entry.v2score, reverse=True)
    entries_v3 = sorted(entries_v3, key=lambda x: x.entry.v3score, reverse=True)

    total_unrated = len(entries_unrated)
    total_v2 = len(entries_v2)
    total_v3 = len(entries_v3)
    total_all = total_unrated + total_v2 + total_v3

    print(Ansi.bold('[*] Found ') + Ansi.red(str(total_all)) + Ansi.bold(' CVE(s)'))
    print(Ansi.bold('[*] ') + Ansi.red(str(total_unrated)) + '/' + Ansi.red(str(total_all)) + Ansi.bold(' CVE(s) in analysis state (no CVSS assigned yet)'))
    for entry in entries_unrated:
        print(entry)
    print(Ansi.bold('[*] ') + Ansi.red(str(total_v3)) + '/' + Ansi.red(str(total_all)) + Ansi.bold(' CVE(s) with CVSS v3 and CVSS v2 score'))
    for entry in entries_v3:
        print(entry)
    print(Ansi.bold('[*] ') + Ansi.red(str(total_v2)) + '/' + Ansi.red(str(total_all)) + Ansi.bold(' CVE(s) with CVSS v2 score only'))
    for entry in entries_v2:
        print(entry)

if __name__ == "__main__":
    main()
