<h1 align="center">cvecheck</h1>
<p align="center">
<strong>A simple tool to query the National Vulnerability Database (NVD) with colors support</strong>
</p>
<p align="center">
<img src="https://img.shields.io/badge/python-3.8-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.9-blue.svg"/>
<img src="https://img.shields.io/badge/License-GPLv3-green.svg"/>
</p>

Often during penetrations tests outdated software components are found and it is necessary to look up whether any Common Vulnerabilities and Exposures (CVE) exist. This simple tool is meant to make this process faster. It allows to query the National Vulnerability Database (NVD) by keyword or by Common Platform Enumeration (CPE) string. The tool prints all (potential more recent) CVEs which have both a CVSS v2 and a CVSS v3 vector assigned first and orders them by severity in reverse order. After that it outputs all CVEs which only have a CVSS v2 score assigned (again in reverse order).

## Installation
```pip install -r requirements.txt```

## Run
### CPE based search
Takes a CPE as argument. A CPE has the following format:

``cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>``

The latest ``cpe_version`` is '2.3'. ``part`` can have the following values:
- ``a`` for applications
- ``h`` for hardware
- ``o`` for operating system

Below is an example where the ``vendor`` and ``product`` are set to 'openssl' with ``version`` '1.0.2f'.

```./cvecheck.py -sC 'cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*'```

### Keyword based search
```./cvecheck.py -sK 'openssl 1.0.2f'```

## Credits
The tool uses vehemont's nvdlib (https://github.com/Vehemont/nvdlib), a python wrapper for the NVD CVE/CPE API.
