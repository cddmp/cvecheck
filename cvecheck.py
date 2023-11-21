#!/usr/bin/env python3
#
# A simple tool to query the National Vulnerability Database (NVD) with colors support.
#
# https://github.com/cddmp/cvecheck

from argparse import ArgumentParser
from enum import Enum
import nvdlib
from jinja2 import Template, Environment
import os
import re
import sys
from uuid import UUID

CVSSV2 = "v2"
CVSSV3 = "v3"

class Colors(Enum):
    bold = '\033[1m'
    underline = '\033[4m'
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    very_red = '\033[101m'

    def __call__(self, string, no_colors=False):
        if no_colors:
            return string
        return f'{self.value}{string}\033[0m'

class Output():
    NO_COLOR = False
    QUIET = False

    @classmethod
    def banner(self):
        if self.QUIET:
            return
        print(Colors.bold(Colors.green('-= CVECHECK =-', self.NO_COLOR), self.NO_COLOR), end='\n\n')

    @classmethod
    def info(self, msg):
        if self.QUIET:
            return

        print(Colors.bold(f'[*] {msg}', self.NO_COLOR))

    @classmethod
    def cves_total(self, total_all):
        if self.QUIET:
            return

        print(Colors.bold('[*] Found ', self.NO_COLOR) + Colors.red(str(total_all), self.NO_COLOR) + Colors.bold(' CVE(s)', self.NO_COLOR))

    @classmethod
    def cves_in_analysis_state(self, total_unrated, total_all):
        if self.QUIET:
            return

        print(Colors.bold('[*] ', self.NO_COLOR) + Colors.red(str(total_unrated), self.NO_COLOR) + '/' + Colors.red(str(total_all), self.NO_COLOR) + Colors.bold(' CVE(s) in analysis state (no CVSS assigned yet)', self.NO_COLOR))

    @classmethod
    def cves_with_both_scores(self, total_v3, total_all):
        if self.QUIET:
            return

        print(Colors.bold('[*] ', self.NO_COLOR) + Colors.red(str(total_v3), self.NO_COLOR) + '/' + Colors.red(str(total_all), self.NO_COLOR) + Colors.bold(' CVE(s) with CVSS v3 and CVSS v2 score', self.NO_COLOR))

    @classmethod
    def hint(self, msg):
        if self.QUIET:
            return

        print(Colors.yellow(f'[*] {msg}', self.NO_COLOR))

    @classmethod
    def error(self, msg):
        if self.QUIET:
            return

        print(Colors.red(f'[!] {msg}', self.NO_COLOR))

    @classmethod
    def cves_with_v2_score_only(self, total_v2, total_all):
        if self.QUIET:
            return

        print(Colors.bold('[*] ', self.NO_COLOR) + Colors.red(str(total_v2), self.NO_COLOR) + '/' + Colors.red(str(total_all), self.NO_COLOR) + Colors.bold(' CVE(s) with CVSS v2 score only', self.NO_COLOR))

class ColoredEntry():
    def __init__(self, entry, template):
        self.entry = entry
        self.template = template
        self.id = self._color_id(entry.id)
        self.url = self.entry.url

        self.v2score = None
        self.v30score = None
        self.v31score = None
        if hasattr(entry, 'v2score'):
            self.v2score =  self._color_score(entry.v2score, False)
        if hasattr(entry, 'v30score'):
            self.v30score = self._color_score(entry.v30score)
            self.entry.v3score = self.entry.v30score
        elif hasattr(entry, 'v31score'):
            self.v31score =  self._color_score(entry.v31score)
            self.entry.v3score = self.entry.v31score

        self.v2severity = None
        self.v30severity = None
        self.v31severity = None
        if hasattr(entry, 'v2severity'):
            self.v2severity =  self._color_severity(entry.v2severity.capitalize())
        if hasattr(entry, 'v30severity'):
            self.v30severity =  self._color_severity(entry.v30severity.capitalize())
        elif hasattr(entry, 'v31severity'):
            self.v31severity =  self._color_severity(entry.v31severity.capitalize())

        self.v2vector = None
        self.v30vector = None
        self.v31vector = None
        if hasattr(entry, 'v2vector'):
            self.v2vector =  f"CVSS:2.0/{entry.v2vector}"
        if hasattr(entry, 'v30vector'):
            self.v30vector =  entry.v30vector
        elif hasattr(entry, 'v31vector'):
            self.v31vector =  entry.v31vector

        self.description = entry.descriptions[0].value.rstrip()

    def __repr__(self):
        env = Environment(trim_blocks=True)
        with open(self.template) as f:
            tmpl = env.from_string(f.read())

        result = tmpl.render(id=self.id,
                             url=self.url,
                             description=self.description,
                             v2score=self.v2score,
                             v30score=self.v30score,
                             v31score=self.v31score,
                             v2severity=self.v2severity,
                             v30severity=self.v30severity,
                             v31severity=self.v31severity,
                             v2vector=self.v2vector,
                             v30vector=self.v30vector,
                             v31vector=self.v31vector)
        return result

    def _color_id(self, cve_id):
        return Colors.underline(Colors.bold(cve_id))
    
    def _color_severity(self, severity):
        mapping = {
                "Low": Colors.green,
                "Medium": Colors.yellow,
                "High": Colors.red,
                "Critical": Colors.very_red,
            }
        return mapping[severity](severity)

    def _color_score(self, score, cvss3=True):
        if score == 0.0:
            return str(score)
        if 0.1 <= score <= 3.9:
            return Colors.green(str(score))
        if 4.0 <= score <= 6.9:
            return Colors.yellow(str(score))
        if not cvss3:
            if 7.0 <= score <= 10.0:
                return Colors.red(str(score))
        if 7.0 <= score <= 8.9:
            return Colors.red(str(score))
        if 9.0 <= score <= 10.0:
            return Colors.very_red(str(score))

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

def abort(msg):
    Output.error(msg)
    exit()

def parse_arguments():
    parser = ArgumentParser(description="""A simple tool to query the National Vulnerability Database (NVD) with colors support.""")
    parser.add_argument('search', help=f'search by keyword (e.g.,"{Colors.bold("OpenSSL 1.0.2f")}"), CVE (e.g.,"{Colors.bold("CVE-2014-0160")}") or CPE (e.g.,"{Colors.bold("cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*")}")')

    mode_switch = parser.add_mutually_exclusive_group()
    mode_switch.add_argument('--cve', action="store_true", help=f'enforce CVE search')
    mode_switch.add_argument('--cpe', action="store_true", help=f'enforce CPE search')
    mode_switch.add_argument('--scpe', action="store_true", help=f'enforce "simplified" CPE search')
    mode_switch.add_argument('--keyword', action="store_true", help=f'enforce keyword search')

    parser.add_argument('--exact-match', dest='exact_match', action='store_true', help=f'return only results which literally match the keyword')
    parser.add_argument('--limit', dest='limit', type=int, help=f'limit the number of results at API level')
    parser.add_argument('--quiet', dest='quiet', action="store_true", default=False, help=f'only print result - will be automatically disabled if input is required')
    parser.add_argument('--template', dest='template', default='examples/default.jinja2', help=f'path to jinja2 template for CVE output')

    parser_metrics = parser.add_mutually_exclusive_group()
    parser_metrics.add_argument('--filter-v2metrics', dest='v2metrics', help=f'filter by CVSS v2 metrics (e.g.,"{Colors.bold("I:P")}")')
    parser_metrics.add_argument('--filter-v3metrics', dest='v3metrics', help=f'filter by CVSS v3 metrics (e.g.,"{Colors.bold("AV:N")}")')

    parser_score = parser.add_mutually_exclusive_group()
    parser_score.add_argument('--filter-v2score', dest='v2score', help=f'filter by CVSS v2 score (e.g.,"{Colors.bold("3.7-5.0")}" or only "{Colors.bold("3.7")}")')
    parser_score.add_argument('--filter-v3score', dest='v3score', help=f'filter by CVSS v3 score (e.g.,"{Colors.bold("3.7-5.0")}" or only "{Colors.bold("3.7")}")')

    parser_severity = parser.add_mutually_exclusive_group()
    parser_severity.add_argument('--filter-v2severity', dest='v2severity', help=f'filter by CVSS v2 severity (e.g.,"{Colors.bold("medium,high")}" or only "{Colors.bold("high")}")')
    parser_severity.add_argument('--filter-v3severity', dest='v3severity', help=f'filter by CVSS v3 severity (e.g.,"{Colors.bold("medium,high")}" or only "{Colors.bold("high")}")')
    parser_severity.add_argument('--filter-cweid', dest='cwe_id', help=f'filter by CWE ID (e.g., "{Colors.bold("CWE-125")}")')


    api_settings = parser.add_argument_group('API settings')
    api_settings.add_argument('--api-key', dest='api_key', default='', help=f'API key for National Vulnerabilities Database (NVD) for faster queries (optional)')
    api_settings.add_argument('--delay', dest='delay', default=None, type=float, help=f'Request delay, by default 6 seconds as requested by NIST, can be lowered to 0.6 seconds when an API key is used')
    args = parser.parse_args()

    if args.api_key and args.delay is not None and args.delay < 0.6:
        parser.error('Delay must be equal or greater than 0.6 seconds')

    if args.api_key:
        try:
            uuid = UUID(args.api_key)
            args.api_key = str(uuid)
        except Exception as e:
            parser.error('Invalid API key given, should be a valid UUID')

    # Ensure args.search does not contain leading or trailing whitespace
    args.search = args.search.strip()

    if not args.cve and not args.cpe and not args.keyword:
        if args.search.lower().startswith('cpe:'):
            args.cpe = True
            args.cve = False
            args.keyword = False

            # NVD API does not like upper case 'CPE:...'
            args.search = args.search.lower()
        elif args.search.lower().startswith('scpe:'):
            args.cpe = True
            args.cve = False
            args.keyword = False

            args.search = f'cpe:2.3:*:{args.search.split(":", 1)[1]}:*:*:*:*:*:*:*'
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

class CveCheck():
    def __init__(self, args):
        self.args = args
        self.entries_v2 = []
        self.entries_v3 = []
        self.entries_unrated = []
        self.cvssV2Severity = False
        self.cvssV3Severity = False

    def run(self):
        if self.args.severity_filter and self.args.severity_filter.single_filter:
            if self.args.severity_filter.version == CVSSV2:
                self.cvssV2Severity = self.args.severity_filter.severities[0]
            elif self.args.severity_filter.version == CVSSV3:
                self.cvssV3Severity = self.args.severity_filter.severities[0]

        if self.args.cve:
            cves = self._search_by_cve()
        elif self.args.keyword:
            cves = self._search_by_keyword()
        elif self.args.cpe:
            cves = self._search_by_cpe()

        if cves is None:
            abort('No CVEs found.')

        for entry in cves:
            if self.args.severity_filter and not self.args.severity_filter.match(entry):
                continue
            if self.args.score_filter and not self.args.score_filter.match(entry):
                continue

            colored_entry = ColoredEntry(entry, self.args.template)
            if not colored_entry.v30score and not colored_entry.v31score and not colored_entry.v2score:
                self.entries_unrated.append(colored_entry)
            elif not colored_entry.v30score and not colored_entry.v31score:
                self.entries_v2.append(colored_entry)
            else:
                self.entries_v3.append(colored_entry)

        # Sort entries by score in reverse order
        self.entries_v2 = sorted(self.entries_v2, key=lambda x: x.entry.v2score, reverse=True)
        self.entries_v3 = sorted(self.entries_v3, key=lambda x: x.entry.v3score, reverse=True)

        total_unrated = len(self.entries_unrated)
        total_v2 = len(self.entries_v2)
        total_v3 = len(self.entries_v3)
        total_all = total_unrated + total_v2 + total_v3

        Output.cves_total(total_all)
        Output.cves_in_analysis_state(total_unrated, total_all)
        for entry in self.entries_unrated:
            print(entry)
        Output.cves_with_both_scores(total_v3, total_all)
        for entry in self.entries_v3:
            print(entry)
        Output.cves_with_v2_score_only(total_v2, total_all)
        for entry in self.entries_v2:
            print(entry)

    def _search_by_cve(self):
        Output.info(f'Searching by CVE...')
        cves = nvdlib.searchCVE(cveId=self.args.search,
                                limit=self.args.limit,
                                delay=self.args.delay,
                                key=self.args.api_key)
        return cves

    def _search_by_keyword(self):
        Output.info(f'Searching by keyword...')
        cves = nvdlib.searchCVE(keywordSearch=self.args.search,
                                cvssV2Metrics=self.args.v2metrics,
                                cvssV3Metrics=self.args.v3metrics,
                                cvssV2Severity=self.cvssV2Severity,
                                cvssV3Severity=self.cvssV3Severity,
                                cweId=self.args.cwe_id,
                                keywordExactMatch=self.args.exact_match,
                                limit=self.args.limit,
                                delay=self.args.delay,
                                key=self.args.api_key)
        return cves

    def _search_by_cpe(self):
        Output.info(f'Searching by CPE...')
        cpes = nvdlib.searchCPE(cpeMatchString=self.args.search,
                                delay=self.args.delay,
                                key=self.args.api_key)

        if len(cpes) == 0:
            abort(f'The given CPE {self.args.search} could not be found.')
        elif len(cpes) > 1:
            Output.QUIET = False
            Output.hint(f'There were {len(cpes)} matching CPEs found. Please choose the right one to continue:')
            for idx, cpe in enumerate(cpes):
                print(f'   {idx+1}: {cpe.cpeName}')

            selection = self._select_cpe(cpes)
            self.args.search = cpes[selection].cpeName
            Output.hint(f'Selected CPE: {self.args.search}')
        else:
            Output.hint(f'Found one matching CPE {cpes[0].cpeName}. Will use that one.')
            self.args.search = cpes[0].cpeName

        cves = nvdlib.searchCVE(cpeName=self.args.search,
                                cvssV2Metrics=self.args.v2metrics,
                                cvssV3Metrics=self.args.v3metrics,
                                cvssV2Severity=self.cvssV2Severity,
                                cvssV3Severity=self.cvssV3Severity,
                                cweId=self.args.cwe_id,
                                keywordExactMatch=self.args.exact_match,
                                limit=self.args.limit,
                                delay=self.args.delay,
                                key=self.args.api_key)
        return cves

    def _select_cpe(self, cpes):
        while True:
            line = sys.stdin.readline().strip()
            try:
                selection = int(line)
                if not  0 < selection <= len(cpes):
                    raise Exception
                break
            except:
                Output.error('Input error. Choose a valid index.')
        return selection-1

def exception_handler(exception):
    exceptions = [
            'Temporary failure in name resolution',
        ]

    result = ''.join([item for item in exceptions if item in str(exception)])
    if not result:
        result = f'Unexpected error:\n\n {str(exception)}.'
    abort(''.join(result))

def main():
    args = parse_arguments()
    Output.QUIET = args.quiet
    if 'NO_COLOR' in os.environ:
        Output.NO_COLOR = True

    Output.banner()

    try:
        cvecheck = CveCheck(args)
        cvecheck.run()
    except Exception as e:
        exception_handler(e)

if __name__ == "__main__":
    main()
