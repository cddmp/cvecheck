#!/usr/bin/env python3
#
# A simple tool to query the National Vulnerability Database (NVD) with colors support.
#
# https://github.com/cddmp/cvecheck

from argparse import ArgumentParser
import nvdlib
import os

COLORS = True
CVSSV2 = "v2"
CVSSV3 = "v3"

class Ansi:
    ansi_reset = '\033[0m'
    ansi_bold = '\033[1m'
    ansi_underline = '\033[4m'
    ansi_red = '\033[91m'
    ansi_green = '\033[92m'
    ansi_yellow = '\033[93m'
    ansi_blue = '\033[94m'
    ansi_very_red = '\033[101m'

    @classmethod
    def red(cls, string):
        if COLORS:
            return f"{cls.ansi_red}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def very_red(cls, string):
        if COLORS:
            return f"{cls.ansi_very_red}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def green(cls, string):
        if COLORS:
            return f"{cls.ansi_green}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def yellow(cls, string):
        if COLORS:
            return f"{cls.ansi_yellow}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def blue(cls, string):
        if COLORS:
            return f"{cls.ansi_blue}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def bold(cls, string):
        if COLORS:
            return f"{cls.ansi_bold}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def underline(cls, string):
        if COLORS:
            return f"{cls.ansi_underline}{string}{cls.ansi_reset}"
        return string

class ColoredEntry():
    def __init__(self, entry):
        self.entry = entry
        self.id = self._color_id(entry.id)
        self.url = self.entry.url

        self.v2score = None
        self.v3score = None
        if hasattr(entry, 'v2score'):
            self.v2score =  self._color_score(entry.v2score, False)
        if hasattr(entry, 'v3score'):
            self.v3score =  self._color_score(entry.v3score)

        self.v2severity = None
        self.v3severity = None
        if hasattr(entry, 'v2severity'):
            self.v2severity =  self._color_severity(entry.v2severity.capitalize())
        if hasattr(entry, 'v3severity'):
            self.v3severity =  self._color_severity(entry.v3severity.capitalize())

        self.v2vector = None
        self.v3vector = None
        if hasattr(entry, 'v2vector'):
            self.v2vector =  f"CVSS:2.0/{entry.v2vector}"
        if hasattr(entry, 'v3vector'):
            self.v3vector =  entry.v3vector

        self.description = entry.cve.description.description_data[0].value

    def __repr__(self):
        result = f"\n{self.id}\n\n"
        if self.v3score:
            result += f"CVSS v3 Base Score: {self.v3score} ({self.v3severity}) ({self.v3vector})\n"
        if self.v2score:
            result += f"CVSS v2 Base Score: {self.v2score} ({self.v2severity}) ({self.v2vector})\n\n"
        if not self.v3score and not self.v2score:
            result += f"CVSS v3 Base Score: unassigned\n"
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
            if not hasattr(entry, 'v3severity'):
                return False
            severity = entry.v3severity
        elif self.version == CVSSV2:
            if not hasattr(entry, 'v3severity'):
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
            if severity in ['low', 'medium', 'high'] or (self.version == 'v3' and severity == 'criticial'):
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
            if not hasattr(entry, 'v3score'):
                return False
            score = entry.v3score
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
    parser.add_argument('search', help=f'search by keyword (e.g.,"{Ansi.bold("OpenSSL 1.0.2f")}") or CPE (e.g.,"{Ansi.bold("cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*")})')

    mode_switch = parser.add_mutually_exclusive_group()
    mode_switch.add_argument('--cpe', action="store_true", help=f'enforce CPE search')
    mode_switch.add_argument('--keyword', action="store_true", help=f'enforce keyword search')

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
    parser.add_argument('--api-key', dest='api_key', default='', help=f'API key for National Vulnerabilities Database (NVD) for faster queries (optional)')
    args = parser.parse_args()

    if not args.cpe and not args.keyword:
        if args.search.lower().startswith('cpe:'):
            args.cpe = True
            args.keyword = False
        else:
            args.cpe = False
            args.keyword = True

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

    if args.keyword:
        print_info(f'Searching by keyword...')
        cves = nvdlib.searchCVE(keyword=args.search,
                                cvssV2Metrics=args.v2metrics,
                                cvssV3Metrics=args.v3metrics,
                                cvssV2Severity=cvssV2Severity,
                                cvssV3Severity=cvssV3Severity,
                                limit=args.limit,
                                key=args.api_key)
    elif args.cpe:
        print_info(f'Searching by CPE...')
        cves = nvdlib.searchCVE(cpeMatchString=args.search,
                                cvssV2Metrics=args.v2metrics,
                                cvssV3Metrics=args.v3metrics,
                                cvssV2Severity=cvssV2Severity,
                                cvssV3Severity=cvssV3Severity,
                                limit=args.limit,
                                key=args.api_key)

    for entry in cves:
        if args.severity_filter and not args.severity_filter.match(entry):
            continue
        if args.score_filter and not args.score_filter.match(entry):
            continue

        colored_entry = ColoredEntry(entry)
        if not colored_entry.v3score and not colored_entry.v2score:
            entries_unrated.append(colored_entry)
        elif not colored_entry.v3score:
            entries_v2.append(colored_entry)
        else:
            entries_v3.append(colored_entry)

    # Sort entries by score in reverse order
    entries_v2 = sorted(entries_v2, key=lambda x: x.entry.v2score, reverse=True)
    entries_v3 = sorted(entries_v3, key=lambda x: x.entry.v3score, reverse=True)

    print(Ansi.bold('[*] Found ') + Ansi.red(str(len(entries_unrated))) + Ansi.bold(' CVE(s) in analysis state (no CVSS assigned yet)'))
    for entry in entries_unrated:
        print(entry)
    print(Ansi.bold('[*] Found ') + Ansi.red(str(len(entries_v3))) + Ansi.bold(' CVE(s) with CVSS v3 and CVSS v2 score'))
    for entry in entries_v3:
        print(entry)
    print(Ansi.bold('[*] Found ') + Ansi.red(str(len(entries_v2))) + Ansi.bold(' CVE(s) with CVSS v2 score only'))
    for entry in entries_v2:
        print(entry)

if __name__ == "__main__":
    main()
