#!/usr/bin/python3
#
# A simple tool to query the National Vulnerability Database (NVD) with colors support.
#
# https://github.com/cddmp/cvecheck

from argparse import ArgumentParser
import nvdlib
import os
import sys

GLOBAL_COLORS = True

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
        if GLOBAL_COLORS:
            return f"{cls.ansi_red}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def very_red(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_very_red}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def green(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_green}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def yellow(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_yellow}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def blue(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_blue}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def bold(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_bold}{string}{cls.ansi_reset}"
        return string

    @classmethod
    def underline(cls, string):
        if GLOBAL_COLORS:
            return f"{cls.ansi_underline}{string}{cls.ansi_reset}"
        return string

class ColoredEntry():
    def __init__(self, entry):
        self.v2_only = False
        
        self.entry = entry
        self.id = self.color_id(entry.id)
        self.url = self.entry.url
        
        self.v2vector = None
        self.v3vector = None
        if hasattr(entry, 'v2vector'):
            self.v2vector =  f"CVSS:2.0/{entry.v2vector}"
        if hasattr(entry, 'v3vector'):
            self.v3vector =  entry.v3vector
        else:
            self.v2_only = True
        
        self.v2score = None
        self.v3score = None
        if hasattr(entry, 'v2score'):
            self.v2score =  self.color_score(entry.v2score, False)
        if hasattr(entry, 'v3score'):
            self.v3score =  self.color_score(entry.v3score)

        self.v2severity = None
        self.v3severity = None
        if hasattr(entry, 'v2severity'):
            self.v2severity =  self.color_severity(entry.v2severity.capitalize())
        if hasattr(entry, 'v3severity'):
            self.v3severity =  self.color_severity(entry.v3severity.capitalize())

        self.description = entry.cve.description.description_data[0].value

    def color_id(self, cve_id):
        return Ansi.underline(Ansi.bold(cve_id))
    
    def color_severity(self, severity):
        mapping = {
                "Low": Ansi.green,
                "Medium": Ansi.yellow,
                "High": Ansi.red,
                "Critical": Ansi.very_red, 
            }
        return mapping[severity](severity)

    def color_score(self, score, cvss3=True):
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

    def __repr__(self):
        result = f"\n{self.id}\n\n"
        if not self.v2_only:
            result += f"CVSS v3 Base Score: {self.v3score} ({self.v3severity}) ({self.v3vector})\n"
        result += f"CVSS v2 Base Score: {self.v2score} ({self.v2severity}) ({self.v2vector})\n\n"
        result += f"{self.url}\n\n"
        result += f"{self.description}\n"
        return result

def print_banner():
    print(Ansi.bold(Ansi.green('-= CVECHECK =-')), end='\n\n')

def print_info(msg):
    print(Ansi.bold(f'[*] {msg}'))

def check_arguments():
    parser = ArgumentParser(description="""A simple tool to query the National Vulnerability Database (NVD) with colors support.""")
    parser.add_argument('-sK', dest='keyword', help=f'search by given keyword (e.g.,"{Ansi.bold("OpenSSL 1.0.2f")}")')
    parser.add_argument('-sC', dest='cpe', help=f'search by given CPE string (e.g.,"{Ansi.bold("cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*")}")')
    parser.add_argument('--api-key', dest='api_key', default='', help=f'API key for National Vulnerabilities Database (NVD) (optional, currently not needed)')
    args = parser.parse_args()

    if not (args.keyword or args.cpe):
        parser.error('expected either -sK or -sC')

    return args

if "NO_COLOR" in os.environ:
    GLOBAL_COLORS = False

print_banner()
args = check_arguments()
entries_v2 = []
entries_v3 = []

if args.keyword:
    print_info(f'Searching by keyword...')
    cves = nvdlib.searchCVE(keyword=args.keyword,key=args.api_key)
elif args.cpe:
    print_info(f'Searching by CPE...')
    cves = nvdlib.searchCVE(cpeMatchString=args.cpe,key=args.api_key)

for entry in cves:
    if not hasattr(entry, 'v3score'):
        entries_v2.append(ColoredEntry(entry))
    else:
        entries_v3.append(ColoredEntry(entry))

# Sort entries by score in reverse order
entries_v2 = sorted(entries_v2, key=lambda x: x.entry.v2score, reverse=True)
entries_v3 = sorted(entries_v3, key=lambda x: x.entry.v3score, reverse=True)

print(Ansi.bold('[*] Found ') + Ansi.red(str(len(entries_v3))) + Ansi.bold(' CVE(s) with CVSS v3 and CVSS v2 score'))
for entry in entries_v3:
    print(entry) 
print(Ansi.bold('[*] Found ') + Ansi.red(str(len(entries_v2))) + Ansi.bold(' CVE(s) with CVSS v2 score only'))
for entry in entries_v2:
    print(entry) 
