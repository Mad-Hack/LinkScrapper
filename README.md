### Free Palestine

# LinkScrapper

**LinkScrapper** is a Python tool for extracting and visualizing endpoints from JavaScript files, web pages, or Burp Suite exports. It is based on LinkFinder but updated for Python3 and added more regex support.

The tool outputs results either:
- Directly to the terminal (`cli` mode), or **HTML report**.

---

## Features

- Parse **remote URLs**, **local JS files**, or entire **folders** of JS.
- Support for **Burp Suite XML exports**.
- Extracts URLs, paths, REST endpoints, and file references with regex.
- Beautifies minified JavaScript for better context extraction.
- CLI or HTML output modes.
- Recursive mode (`--domain`) to automatically fetch and scan discovered JS files.
- Optional cookies for authenticated endpoints.
- Handles gzip/deflate responses.
- **Insecure mode** (`--insecure`) for invalid SSL certificates.

---

## Installation

Clone the repo and install requirements:

```
git clone https://github.com/Mad-Hack/LinkScrapper.git
cd LinkScrapper
pip install -r requirements.txt
```
```
└─# python3 linkscrap.py -h

usage: linkscrap.py [-h] [-d] -i INPUT [-o OUTPUT] [-r REGEX] [-b] [-c COOKIES] [-t TIMEOUT] [--insecure]

options:
  -h, --help            show this help message and exit
  -d, --domain          Recursively parse all JavaScript on a page
  -i, --input INPUT     Input: URL, file, or wildcard (e.g. '*.js')
  -o, --output OUTPUT   Output file (default: output.html) or 'cli' for stdout
  -r, --regex REGEX     Regex to filter found endpoints (e.g. ^/api/)
  -b, --burp            Parse Burp XML file
  -c, --cookies COOKIES
                        Add cookies for authenticated JS files
  -t, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  --insecure            Disable SSL certificate verification (UNSAFE). Use only if you understand the risk.
```
