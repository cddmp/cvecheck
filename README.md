<h1 align="center">cvecheck</h1>
<p align="center">
<strong>A simple tool to query the National Vulnerability Database (NVD) with colors support</strong>
</p>
<p align="center">
<img src="https://img.shields.io/badge/python-%3E=_3.8-blue"/>
<img src="https://img.shields.io/badge/License-GPLv3-green.svg"/>
</p>

Often during penetration tests, outdated software components are found and it is necessary to look up whether any Common Vulnerabilities and Exposures (CVE) exists to examine and document them. This simple tool is meant to make this process faster.

It allows to query the National Vulnerability Database (NVD) by keyword, CVE ID, Common Platform Enumeration (CPE) string or "simplified" CPE (see further down). The tool detects the correct mode automatically.
The output is generated via Jinja2 templates. This allows to create your own output templates in order to get custom output formatting (see examples folder). In addition, the terminal output is colored (can be disabled via [NO_COLOR](https://no-color.org/) environment variable).

Currently it outputs CVEs in three groups:
- CVEs which are still under analysis (no CVSS vector assigned)
- CVEs with both a CVSS v3.1/v3.0 and a CVSS v2 vector
- CVEs with a CVSS v2 vector only

By default, the last two groups are sorted by score in descending order.

## Installation
```pip install -r requirements.txt```

## Run

### CVE search
The tool automatically searches for a specific CVE if the given keyword starts with 'CVE-' (case agnostic).

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

If the CPE is not unique and would therefore match different CPEs in the NVD database, a list of possible CPEs will be shown, where one needs to be selected. If a wildcard is being used and only one CPE would match, then this CPE is automatically selected for the search and the tool will continue without showing any prompt.

### 'Simplified' CPE search
The CPE strings are very long and hard to remember. Therefore it supports, what I call, 'simplified' CPE strings. These strings have the following format:

``scpe:<vendor>:<product>:<version>``

As with the normal CPE, stars can be used as wild cards. Below is an example where ``vendor`` is set to '*', ``product`` is set to 'openssl' and ``version`` is '1.0.2f'.

Apart from that, the same applies as with the CPE search described above.

```./cvecheck.py 'scpe:*:openssl:1.0.2f''```

### Keyword based search
If the keyword does not start with 'CVE-', 'cpe:' or 'scpe:', the keyword based search will be used.

```./cvecheck.py 'openssl 1.0.2f'```

## Filter
Various filters are supported. Results can be filtered by metrics, vector or score. 

### Metrics filter
The metrics filter is passed directly to the API. All the filtering happens therefore at the API backend. The following example filters for all CVEs with attack vector 'Network'.

```./cvecheck.py 'scpe:openssl:openssl:1.0.2f' --filter-v3metrics 'AV:N'```

### Score filter
The tool allows to filter by score, which is not supported by the NVD API. Therefore, the filter is applied locally once the CVEs have been fetched from the API. The filter allows to either filter by range or by a single value:

```./cvecheck.py 'scpe:openssl:openssl:1.0.2f' --filter-v3score '7.5'```

```./cvecheck.py 'scpe:openssl:openssl:1.0.2f' --filter-v3score '4.0-6.9'```

### Severity filter
The NVD API only allows to filter by one severity (e.g., 'MEDIUM'). The tool allows to filter by several severity values. If only one severity is being passed the filtering will happen at the API. In all other cases (multiple severity values being passed), the filtering will happen locally:

```./cvecheck.py 'scpe:openssl:openssl:1.0.2f' --filter-v3severity high,critical```

### Template based output
Sometimes one needs a more verbose output like the CVE ID, the base scores as well as the description. Sometimes, e.g, for a table in a report, one only needs a list of CVEs without any description but with most recent CVSS base scores. For this, template support was added. Some examples are in the example directory. The templates can be simply passed with the ``--template`` parameter. By default the default.jinja2 template will be used (again see examples directory).

### API key
The NVD API supports keys which can be passed with the ``--api-key`` parameter. A key can be obtained for free from here: https://nvd.nist.gov/developers/request-an-api-key

#### Important notes
It should be noted, that it might take some minutes for the key to become active, once it was obtained via the link above. If the key is not activated, the API currently returns an HTTP 404. The tool will print that out. Try again after some minutes. Once the key works, it will work all the time.

The NVD API by default delays any request for 6 seconds, if no API key is used. When an API key is used, the delay will be lowered to 0.6 seconds. The tool reflects that with the ``--delay`` parameter.
Still, it should be noted that NIST published best practices for the API. These best practices state that users should "sleep" their scripts for 6 seconds between requests (see https://nvd.nist.gov/developers/start-here). Therefore, if the script is run in parallel or in a loop it should be ensured that this timing is kept.

## Credits
The tool uses vehemont's nvdlib (https://github.com/Vehemont/nvdlib), a python wrapper for the NVD CVE/CPE API.
