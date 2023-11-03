<h1 align="center">cvecheck</h1>
<p align="center">
<strong>A simple tool to query the National Vulnerability Database (NVD) with colors support</strong>
</p>
<p align="center">
<img src="https://img.shields.io/badge/python-3.8-blue.svg"/>
<img src="https://img.shields.io/badge/python-3.9-blue.svg"/>
<img src="https://img.shields.io/badge/License-GPLv3-green.svg"/>
</p>

Often during penetration tests, outdated software components are found and it is necessary to look up whether any Common Vulnerabilities and Exposures (CVE) exists. This simple tool is meant to make this process faster. It allows to query the National Vulnerability Database (NVD) by keyword or by Common Platform Enumeration (CPE) string. The tool detects the correct mode automatically. Currently it outputs CVEs in three groups:
- CVEs which are still under analysis (no CVSS vector assigned)
- CVEs with both a CVSS v3.1/v3.0 and a CVSS v2 vector
- CVEs with a CVSS v2 vector only

By default, the last two groups are sorted by score in descending order.

## Installation
```pip install -r requirements.txt```

## Run

### CVE search
The tool automatically searches for a specific CVE if the keyword starts with 'CVE-' (case agnostic).

```./cvecheck.py 'CVE-2014-0160'```

### CPE based search
The tool automatically does a CPE based search if the keyword starts with 'cpe:' (case agnostic). A CPE strings has the following format:

``cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>``

The latest ``cpe_version`` is '2.3'. ``part`` can have the following values:
- ``a`` for applications
- ``h`` for hardware
- ``o`` for operating system

Below is an example where the ``vendor`` and ``product`` are set to 'openssl' with ``version`` '1.0.2f'.

```./cvecheck.py 'cpe:2.3:a:openssl:openssl:1.0.2f:*:*:*:*:*:*:*'```

### Keyword based search
If the keyword does not start with 'CPE:', the keyword based search will be used.

```./cvecheck.py 'openssl 1.0.2f'```

CVE, CPE and keyword based search can also be enforced by either passing ``--cve``, ``--cpe`` or ``--keyword``.

## Filter
Various filters are supported. Results can be filtered by metrics, vector or score. 

### Metrics filter
The metrics filter is passed directly to the API. All the filtering happens therefore at the API backend. The following example filters for all CVEs with attack vector 'Network'.

```./cvecheck.py --filter-v3metrics 'AV:N'```

### Score filter
The API does not support filtering by score. Therefore, the filter is applied locally once the CVEs have been fetched from the API. The filter allows to either filter by range or by a single value:

```./cvecheck.py --filter-v3score '7.5'```
```./cvecheck.py --filter-v3score '4.0-6.9'```

### Severity filter
The API only allows to filter by one severity (e.g., 'MEDIUM'). The tool allows to filter by several severity values. If only one severity is being passed the filtering will happen at the API. In all other cases (multiple severity values being passed), the filtering will happen locally:

```./cvecheck.py --filter-v3severity 'critical'```
```./cvecheck.py --filter-v3severity 'high,critical'```


## Credits
The tool uses vehemont's nvdlib (https://github.com/Vehemont/nvdlib), a python wrapper for the NVD CVE/CPE API.
