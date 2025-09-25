#!/usr/bin/env python3

import os
import re
import sys
import glob
import html
import ssl
import base64
import argparse
import subprocess
import webbrowser
import zlib
import xml.etree.ElementTree as ET

from io import BytesIO
from gzip import GzipFile
from string import Template
from urllib.request import Request, urlopen
from urllib.error import URLError

import jsbeautifier

import logging
logging.basicConfig(level=logging.INFO)

readBytesCustom = BytesIO

regex_str = r"""
  (?:"|'|`)                           # Start delimiter: ", ' or backtick

  (
    # Absolute URL with protocol or protocol-relative
    (?:(?:[a-zA-Z]{1,10}://|//)[^"'/]+\.[a-zA-Z]{2,}[^"' ]*)

    |

    # Path starting with /, ../, or ./
    (?:(?:/|\.\./|\./)[^"'><,;|()*$^\[\] ]+)

    |

    # Relative endpoint with extension
    (?:[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+\.(?:[a-zA-Z]{1,6}|action)(?:[\?#][^"' ]*)?)

    |

    # REST-style endpoint without extension
    (?:[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]{3,}(?:[\?#][^"' ]*)?)

    |

    # Filenames with sensitive extensions
    (?:[a-zA-Z0-9_\-]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|cfg|conf|ini|env|yaml|yml)(?:[\?#][^"' ]*)?)

  )

  (?:"|'|`)                           # End delimiter: ", ' or backtick
"""

REGEX = re.compile(regex_str, re.VERBOSE)

context_delimiter_str = "\n"

def parser_error(errmsg: str) -> None:
    """
    Print a usage hint and exit with error code 1.
    """
    print(f"Usage: {sys.argv[0]} [options] (use -h for help)")
    print(f"Error: {errmsg}")
    sys.exit(1)

def parser_input(src):
    """
    Parse input argument and return a list of inputs.

    Returns:
      - For normal URLs/files: list of strings (each a URL, or file://... path)
      - For Burp XML (`--burp`): list of dicts: {"js": "...", "url": "..."}
    """
    # normalize and expand user paths
    if isinstance(src, str):
        src = os.path.expanduser(src.strip())
    else:
        parser_error("input must be a string")

    # If src looks like a text file with URLs/domains, treat each line as an input
    if os.path.exists(src) and not src.startswith(("http://", "https://", "file://", "ftp://", "ftps://")):
        try:
            with open(src, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            if lines and all(not l.startswith("file://") for l in lines):
                return lines
        except Exception as e:
            parser_error(f"Could not read input file {src}: {e}")

    # Method 1 - Absolute URL or file URL
    if src.startswith(('http://', 'https://', 'file://', 'ftp://', 'ftps://')):
        return [src]

    # Method 2 - Firefox view-source:
    if src.startswith('view-source:'):
        return [src[len('view-source:'):]]
    
    # Method 3 - Burp XML export (explicit flag required)
    if args.burp:
        jsfiles = []
        try:
            with open(src, "r", encoding="utf-8") as f:
                xml_text = f.read()
            root = ET.fromstring(xml_text)
        except FileNotFoundError:
            parser_error(f"Burp file not found: {src}")
        except ET.ParseError as e:
            parser_error(f"Failed to parse Burp XML: {e}")

        for item in root.findall('.//item') if root is not None else root:
            # adjust path to response/url elements depending on Burp structure
            resp = item.find('response')
            url_el = item.find('url')
            if resp is None or url_el is None:
                continue
            try:
                js_content = base64.b64decode(resp.text).decode('utf-8', 'replace')
            except Exception:
                js_content = base64.b64decode(resp.text or b'').decode('utf-8', 'replace')
            jsfiles.append({"js": js_content, "url": url_el.text})
        return jsfiles

    # Method 4 - Wildcard (folder)
    if '*' in src or '?' in src or os.path.isdir(src):
        # if a directory given, grab files recursively? keep original behaviour: glob
        paths = glob.glob(os.path.abspath(src))
        if not paths:
            parser_error(f"Input with wildcard does not match any files: {src}")
        # convert to file:// paths
        file_urls = [f"file://{p}" for p in paths]
        return file_urls

    # Method 5 - Local file (plain path)
    if os.path.exists(src):
        return [f"file://{os.path.abspath(src)}"]

    # If nothing matched, give a helpful error
    parser_error("file could not be found (maybe you forgot to add http/https).")

logger = logging.getLogger(__name__)

def send_request(url, allow_legacy_fallback=False):
    """
    Fetch `url` and return decoded text (str).
    - allow_legacy_fallback: if True, will try insecure TLSv1 fallback on TLS handshake failure.
      Default: False (do NOT downgrade).
    Raises urllib.error.URLError / ssl.SSLError on network/TLS problems.
    """
    q = Request(url)
    q.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
    q.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
    q.add_header('Accept-Language', 'en-US,en;q=0.8')
    # advertise both gzip and deflate
    q.add_header('Accept-Encoding', 'gzip, deflate')
    q.add_header('Cookie', args.cookies)

    # build TLS client context (allow opt-in insecure mode)
    if getattr(args, "insecure", False):
        # WARNING: insecure mode — disables all cert verification & hostname checks
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        try:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            try:
                # available in Python 3.7+
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                # best-effort fallback
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # try request, optionally fallback to legacy (insecure) TLS on handshake failure
    try:
        resp = urlopen(q, timeout=args.timeout, context=ctx)
    except ssl.SSLError as e:
        logger.warning("TLS handshake failed for %s: %s", url, e)
        if not allow_legacy_fallback:
            raise
        logger.warning("Attempting legacy TLSv1 fallback for %s (INSECURE).", url)
        try:
            legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # explicit insecure fallback
            resp = urlopen(q, timeout=args.timeout, context=legacy_ctx)
        except Exception as e2:
            logger.error("Legacy TLS fallback failed for %s: %s", url, e2)
            raise
    except URLError:
        # let caller handle URLError / HTTPError
        raise

    # Read bytes exactly once
    raw = resp.read() or b''

    # Determine encodings (handles "gzip", "deflate", "gzip, deflate", etc.)
    encoding_header = ''
    try:
        encoding_header = (resp.info().get('Content-Encoding') or '').lower()
    except Exception:
        encoding_header = ''

    encodings = [e.strip() for e in encoding_header.split(',')] if encoding_header else []

    # Decode according to encoding
    try:
        if 'gzip' in encodings:
            data_bytes = GzipFile(fileobj=BytesIO(raw)).read()
        elif 'deflate' in encodings:
            try:
                data_bytes = zlib.decompress(raw)
            except zlib.error:
                # try raw deflate stream
                data_bytes = zlib.decompress(raw, -zlib.MAX_WBITS)
        else:
            data_bytes = raw
    except Exception as e:
        logger.warning("Failed to decode content-encoding '%s' for %s: %s — falling back to raw bytes",
                       encoding_header, url, e)
        data_bytes = raw

    # Try to detect charset from headers; fall back to utf-8
    charset = None
    try:
        # resp.getheaders / resp.headers differs by version; try safe paths
        if hasattr(resp, "headers") and hasattr(resp.headers, "get_content_charset"):
            charset = resp.headers.get_content_charset()
        else:
            # older compatibility: parse charset from Content-Type header
            ct = resp.info().get('Content-Type', '') or ''
            if 'charset=' in ct:
                charset = ct.split('charset=')[-1].split(';')[0].strip()
    except Exception:
        charset = None

    if not charset:
        charset = 'utf-8'

    return data_bytes.decode(charset, 'replace')

def getContext(list_matches, content, include_delimiter=False, context_delimiter="\n"):
    """
    Extract context lines (or delimiter-bounded segments) around each regex match.

    Args:
        list_matches: list of tuples (match_str, start_index, end_index)
        content: the full string searched
        include_delimiter: if True, include the delimiter character(s) in the returned context
        context_delimiter: string delimiter, default newline
    Returns:
        list of dicts: [{"link": match_str, "context": context}, ...]
    """
    items = []
    delim = context_delimiter

    for match_str, start_idx, end_idx in list_matches:
        # find nearest delimiter before and after
        context_start = content.rfind(delim, 0, start_idx)
        context_end = content.find(delim, end_idx)

        if context_start == -1:
            context_start = 0
        else:
            if not include_delimiter:
                context_start += len(delim)

        if context_end == -1:
            context_end = len(content)

        context = content[context_start:context_end]

        items.append({
            "link": match_str,
            "context": context
        })

    return items

def parser_file(content, regex=REGEX, mode=1, more_regex=None, no_dup=True, delimiter="\n"):
    """
    Parse JS/HTML content to extract potential endpoints.
    Returns list of dicts: {"link": str, "context": str (optional)}.
    """
    # Optionally beautify
    if mode == 1:
        try:
            if len(content) > 1_000_000:
                content = content.replace(";", ";\r\n").replace(",", ",\r\n")
            else:
                content = jsbeautifier.beautify(content)
        except Exception as e:
            # fallback: use raw content if beautifier fails
            print(f"[!] Beautify failed: {e}")
    
    # Run regex
    if mode == 1:
        all_matches = [(m.group(1), m.start(0), m.end(0)) for m in regex.finditer(content)]
        items = getContext(all_matches, content, context_delimiter=delimiter)
    else:
        items = [{"link": m.group(1)} for m in regex.finditer(content)]

    # Apply filter regex if given
    if more_regex:
        items = [item for item in items if re.search(more_regex, item["link"])]

    # Deduplicate if needed
    if no_dup:
        seen = {}
        for item in items:
            if item["link"] not in seen:
                seen[item["link"]] = item
        items = list(seen.values())

    return items

def cli_output(endpoints):
    """
    Print extracted endpoints to CLI.
    """
    for endpoint in endpoints:
        # preserve non-ASCII instead of dropping
        safe_link = html.escape(endpoint["link"])
        print(safe_link)

def html_save(html: str) -> str:
    """
    Save HTML output to a file and try to open it in a browser (Linux: xdg-open).
    Returns the absolute path to the saved file.
    """
    try:
        template_path = os.path.join(os.path.dirname(__file__), "template.html")
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template file not found: {template_path}")

        with open(template_path, "r", encoding="utf-8") as tpl_file:
            template = Template(tpl_file.read())

        output_path = os.path.abspath(args.output)
        with open(output_path, "wb") as text_file:
            text_file.write(template.substitute(content=html).encode("utf-8"))

        print(f"URL to access output: file://{output_path}")

        file_url = f"file:///{output_path}"
        if sys.platform.startswith("linux"):
            subprocess.Popen(
                ["xdg-open", file_url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            webbrowser.open(file_url)

        return output_path

    except Exception as e:
        print(f"[!] Output can't be saved in {args.output} due to: {e}")
        return ""

from urllib.parse import urljoin

def normalize_js_url(url: str, base: str) -> str | None:
    """
    Normalize and filter JavaScript URLs.
    - Skips unwanted files (e.g. node_modules, jquery.js).
    - Expands protocol-relative (//...) to https://...
    - Resolves relative paths against the given base URL.
    
    Args:
        url:  candidate URL or path
        base: base URL (e.g. args.input)
    
    Returns:
        str absolute URL, or None if excluded/invalid
    """
    nopelist = {"node_modules", "jquery.js"}

    if not url.lower().endswith(".js"):
        return None

    # filter out unwanted paths
    if any(part in nopelist for part in url.split("/")):
        return None

    # protocol-relative → assume https
    if url.startswith("//"):
        return "https:" + url

    # absolute already
    if url.lower().startswith("http"):
        return url

    # relative → resolve against base
    return urljoin(base, url)

def render_html_section(file_url, endpoints):
    section = f"""
        <h1>File: <a href="{html.escape(file_url)}" target="_blank" rel="nofollow noopener noreferrer">{html.escape(file_url)}</a></h1>
    """
    for ep in endpoints:
        link = html.escape(ep["link"])
        context = html.escape(ep.get("context", ""))

        # replace plain link text in context with a clickable <a>
        highlighted_context = context.replace(
            link,
            f"<a href='{link}' target='_blank' class='highlight'>{link}</a>"
        )

        section += f"""
            <div>
                <a href="{link}" target="_blank" class="text">{link}</a>
                <div class="container">{highlighted_context}</div>
            </div>
        """
    return section

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Recursively parse all JavaScript on a page", action="store_true")
    parser.add_argument("-i", "--input", help="Input: URL, file, or wildcard (e.g. '*.js')", required=True)
    parser.add_argument("-o", "--output", help="Output file (default: output.html) or 'cli' for stdout", default="output.html")
    parser.add_argument("-r", "--regex", help="Regex to filter found endpoints (e.g. ^/api/)")
    parser.add_argument("-b", "--burp", help="Parse Burp XML file", action="store_true")
    parser.add_argument("-c", "--cookies", help="Add cookies for authenticated JS files", default="")
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds (default: 10)", default=10, type=int)
    parser.add_argument("--insecure", help="Disable SSL certificate verification (UNSAFE). Use only if you understand the risk.", action="store_true")
    args = parser.parse_args()

    mode = 0 if args.output == "cli" else 1
    urls = parser_input(args.input)

    output_html = ""

    for url in urls:
        if args.burp:
            file_content, file_url = url["js"], url["url"]
        else:
            try:
                file_content, file_url = send_request(url), url
            except Exception as e:
                print(f"[!] Failed to fetch {url}: {e}")
                continue

        endpoints = parser_file(file_content, REGEX, mode, args.regex)

        # recursive domain mode
        if args.domain:
            for ep in endpoints:
                normalized = normalize_js_url(ep["link"], file_url)
                if not normalized:
                    continue
                print(f"\nRunning against: {normalized}\n")
                try:
                    rec_content = send_request(normalized)
                    new_endpoints = parser_file(rec_content, REGEX, mode, args.regex)
                    if args.output == "cli":
                        cli_output(new_endpoints)
                    else:
                        output_html += render_html_section(normalized, new_endpoints)
                except Exception as e:
                    print(f"[!] Failed to fetch {normalized}: {e}")

        # normal output
        if args.output == "cli":
            cli_output(endpoints)
        else:
            output_html += render_html_section(file_url, endpoints)

    if args.output != "cli":
        html_save(output_html)
