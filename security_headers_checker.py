#!/usr/bin/env python3
"""
Security Headers Checker - A CLI tool to detect missing or misconfigured security headers
"""

import sys
import re
import requests
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = typer.Typer(help="Security Headers Checker CLI")
console = Console()

@dataclass
class HeaderInfo:
    name: str
    description: str
    risk_level: str  # "high", "medium", "low"
    validator: Any  # Function to validate the header value
    recommendation: str

@dataclass
class HeaderResult:
    header: HeaderInfo
    value: Optional[str]
    is_present: bool
    is_valid: bool
    validation_message: Optional[str] = None

@dataclass
class RedirectInfo:
    url: str
    status_code: int
    headers: Dict[str, str]

def validate_csp(value: str) -> Tuple[bool, Optional[str]]:
    """Validate Content-Security-Policy header."""
    if not value:
        return False, "Header is empty"
    
    # Check for 'unsafe-inline' or 'unsafe-eval' in script-src
    if "script-src" in value and ("unsafe-inline" in value or "unsafe-eval" in value):
        return False, "Contains unsafe-inline or unsafe-eval in script-src"
    
    # Check for default-src or script-src
    if "default-src" not in value and "script-src" not in value:
        return False, "Missing default-src or script-src directive"
    
    # Check if using report-uri instead of report-to
    if "report-uri" in value and "report-to" not in value:
        return False, "Using deprecated report-uri without report-to"
    
    return True, None

def validate_hsts(value: str) -> Tuple[bool, Optional[str]]:
    """Validate Strict-Transport-Security header."""
    if not value:
        return False, "Header is empty"
    
    # Check for max-age
    max_age_match = re.search(r'max-age=(\d+)', value)
    if not max_age_match:
        return False, "Missing max-age directive"
    
    max_age = int(max_age_match.group(1))
    if max_age < 15768000:  # 6 months in seconds
        return False, f"max-age too short: {max_age} (recommended: at least 15768000)"
    
    # Check for includeSubDomains
    if "includeSubDomains" not in value:
        return False, "Missing includeSubDomains directive"
    
    # Check for preload
    if "preload" not in value:
        return False, "Missing preload directive (optional but recommended)"
    
    return True, None

def validate_xfo(value: str) -> Tuple[bool, Optional[str]]:
    """Validate X-Frame-Options header."""
    if not value:
        return False, "Header is empty"
    
    value = value.upper()
    if value not in ["DENY", "SAMEORIGIN"]:
        return False, f"Invalid value: {value} (should be DENY or SAMEORIGIN)"
    
    return True, None

def validate_xcto(value: str) -> Tuple[bool, Optional[str]]:
    """Validate X-Content-Type-Options header."""
    if not value:
        return False, "Header is empty"
    
    if value.lower() != "nosniff":
        return False, f"Invalid value: {value} (should be nosniff)"
    
    return True, None

def validate_referrer_policy(value: str) -> Tuple[bool, Optional[str]]:
    """Validate Referrer-Policy header."""
    if not value:
        return False, "Header is empty"
    
    valid_values = [
        "no-referrer", "no-referrer-when-downgrade", "origin", 
        "origin-when-cross-origin", "same-origin", "strict-origin", 
        "strict-origin-when-cross-origin", "unsafe-url"
    ]
    
    if value.lower() not in valid_values:
        return False, f"Invalid value: {value}"
    
    if value.lower() in ["unsafe-url", "no-referrer-when-downgrade"]:
        return False, f"Weak policy: {value}"
    
    return True, None

def validate_permissions_policy(value: str) -> Tuple[bool, Optional[str]]:
    """Validate Permissions-Policy header."""
    if not value:
        return False, "Header is empty"
    
    # Basic check for format
    if not re.search(r'[a-z-]+=[^,]+', value):
        return False, "Invalid format"
    
    return True, None

def validate_cache_control(value: str) -> Tuple[bool, Optional[str]]:
    """Validate Cache-Control header."""
    if not value:
        return False, "Header is empty"
    
    directives = [d.strip().lower() for d in value.split(",")]
    
    # Check for private or no-store
    if "private" not in directives and "no-store" not in directives:
        return False, "Missing private or no-store directive"
    
    return True, None

# Define headers to check
HEADERS_TO_CHECK = [
    HeaderInfo(
        name="Content-Security-Policy",
        description="Controls resources the user agent is allowed to load",
        risk_level="high",
        validator=validate_csp,
        recommendation="Use a strong CSP that avoids unsafe-inline and unsafe-eval"
    ),
    HeaderInfo(
        name="Strict-Transport-Security",
        description="Enforces secure (HTTPS) connections to the server",
        risk_level="high",
        validator=validate_hsts,
        recommendation="max-age=31536000; includeSubDomains; preload"
    ),
    HeaderInfo(
        name="X-Frame-Options",
        description="Protects against clickjacking attacks",
        risk_level="medium",
        validator=validate_xfo,
        recommendation="DENY or SAMEORIGIN"
    ),
    HeaderInfo(
        name="X-Content-Type-Options",
        description="Prevents MIME type sniffing",
        risk_level="medium",
        validator=validate_xcto,
        recommendation="nosniff"
    ),
    HeaderInfo(
        name="Referrer-Policy",
        description="Controls how much referrer information should be included with requests",
        risk_level="medium",
        validator=validate_referrer_policy,
        recommendation="strict-origin-when-cross-origin"
    ),
    HeaderInfo(
        name="Permissions-Policy",
        description="Controls which browser features can be used (formerly Feature-Policy)",
        risk_level="medium",
        validator=validate_permissions_policy,
        recommendation="camera=(), microphone=(), geolocation=(), interest-cohort=()"
    ),
    HeaderInfo(
        name="Cache-Control",
        description="Directives for caching mechanisms in requests/responses",
        risk_level="low",
        validator=validate_cache_control,
        recommendation="no-store, max-age=0"
    ),
]

def fetch_headers(url: str, follow_redirects: bool = True) -> List[RedirectInfo]:
    """Fetch headers from a URL, optionally following redirects."""
    redirect_chain = []
    
    try:
        # Initial request with allow_redirects=False to manually handle redirects
        response = requests.get(
            url, 
            headers={
                'User-Agent': 'SecurityHeadersChecker/1.0 (https://github.com/yourusername/security-headers-checker)'
            },
            allow_redirects=False,
            timeout=10,
            verify=False  # Skip SSL verification
        )
        
        # Add initial response to redirect chain
        redirect_chain.append(RedirectInfo(
            url=url,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()}
        ))
        
        # Follow redirects if enabled
        if follow_redirects:
            current_url = url
            max_redirects = 10
            redirect_count = 0
            
            while 300 <= response.status_code < 400 and redirect_count < max_redirects:
                redirect_count += 1
                
                if 'location' in response.headers:
                    redirect_url = response.headers['location']
                    
                    # Handle relative URLs
                    if not redirect_url.startswith(('http://', 'https://')):
                        parsed_url = urlparse(current_url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        redirect_url = base_url + redirect_url
                    
                    current_url = redirect_url
                    
                    response = requests.get(
                        redirect_url,
                        headers={
                            'User-Agent': 'SecurityHeadersChecker/1.0 (https://github.com/yourusername/security-headers-checker)'
                        },
                        allow_redirects=False,
                        timeout=10,
                        verify=False
                    )
                    
                    redirect_chain.append(RedirectInfo(
                        url=redirect_url,
                        status_code=response.status_code,
                        headers={k.lower(): v for k, v in response.headers.items()}
                    ))
                else:
                    break
    
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error fetching URL:[/bold red] {str(e)}")
        sys.exit(1)
    
    return redirect_chain

def analyze_headers(redirect_chain: List[RedirectInfo]) -> List[HeaderResult]:
    """Analyze headers for security issues."""
    results = []
    
    # Use the headers from the final response in the redirect chain
    final_headers = redirect_chain[-1].headers
    
    for header_info in HEADERS_TO_CHECK:
        header_name = header_info.name.lower()
        header_value = final_headers.get(header_name)
        
        is_present = header_name in final_headers
        is_valid = False
        validation_message = None
        
        if is_present:
            is_valid, validation_message = header_info.validator(header_value)
        
        results.append(HeaderResult(
            header=header_info,
            value=header_value,
            is_present=is_present,
            is_valid=is_valid,
            validation_message=validation_message
        ))
    
    return results

def get_risk_color(risk_level: str) -> str:
    """Get color based on risk level."""
    return {
        "high": "red",
        "medium": "yellow",
        "low": "green"
    }.get(risk_level, "white")

def get_status_color(is_present: bool, is_valid: bool) -> str:
    """Get color based on header status."""
    if not is_present:
        return "red"
    if not is_valid:
        return "yellow"
    return "green"

def get_status_symbol(is_present: bool, is_valid: bool) -> str:
    """Get symbol based on header status."""
    if not is_present:
        return "✗"
    if not is_valid:
        return "⚠"
    return "✓"

def display_results(url: str, redirect_chain: List[RedirectInfo], results: List[HeaderResult]):
    """Display analysis results in a nice format."""
    # Display header
    console.print(Panel(
        f"[bold]Security Headers Analysis for:[/bold] [cyan]{url}[/cyan]",
        expand=False
    ))
    
    # Display redirect chain if there are redirects
    if len(redirect_chain) > 1:
        redirect_table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
        redirect_table.add_column("Step")
        redirect_table.add_column("URL")
        redirect_table.add_column("Status")
        
        for i, redirect in enumerate(redirect_chain):
            status_color = "green" if 200 <= redirect.status_code < 300 else \
                          "yellow" if 300 <= redirect.status_code < 400 else "red"
            
            redirect_table.add_row(
                f"{i+1}",
                redirect.url,
                f"[{status_color}]{redirect.status_code}[/{status_color}]"
            )
        
        console.print(Panel(redirect_table, title="[bold]Redirect Chain[/bold]", expand=False))
    
    # Display detailed results
    results_table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
    results_table.add_column("Status")
    results_table.add_column("Header")
    results_table.add_column("Risk")
    results_table.add_column("Present")
    results_table.add_column("Value")
    results_table.add_column("Issue")
    
    for result in results:
        status_color = get_status_color(result.is_present, result.is_valid)
        status_symbol = get_status_symbol(result.is_present, result.is_valid)
        risk_color = get_risk_color(result.header.risk_level)
        
        results_table.add_row(
            f"[{status_color}]{status_symbol}[/{status_color}]",
            result.header.name,
            f"[{risk_color}]{result.header.risk_level.upper()}[/{risk_color}]",
            "Yes" if result.is_present else "No",
            Text(result.value or "", no_wrap=False, overflow="fold"),
            result.validation_message or ("Missing" if not result.is_present else "")
        )
    
    console.print(Panel(results_table, title="[bold]Header Analysis[/bold]", expand=False))
    
    # Display recommendations for missing or misconfigured headers
    recommendations = []
    for result in results:
        if not result.is_present or not result.is_valid:
            recommendations.append({
                "header": result.header.name,
                "description": result.header.description,
                "recommendation": result.header.recommendation,
                "issue": result.validation_message or "Missing"
            })
    
    if recommendations:
        rec_table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
        rec_table.add_column("Header")
        rec_table.add_column("Description")
        rec_table.add_column("Issue")
        rec_table.add_column("Recommendation")
        
        for rec in recommendations:
            rec_table.add_row(
                rec["header"],
                rec["description"],
                rec["issue"],
                rec["recommendation"]
            )
        
        console.print(Panel(rec_table, title="[bold]Recommendations[/bold]", expand=False))

def validate_url(url: str) -> str:
    """Validate and normalize URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL")
    except Exception:
        raise typer.BadParameter(f"Invalid URL: {url}")
    
    return url

@app.command()
def check(
    url: str = typer.Argument(None, help="URL to check for security headers"),
    follow_redirects: bool = typer.Option(True, "--follow-redirects/--no-follow-redirects", "-r/-nr", help="Follow redirects")
):
    """Check security headers for a given URL."""
    if not url:
        if not typer.confirm("No URL provided. Do you want to enter interactive mode?"):
            raise typer.Abort()
        return interactive_mode()
    
    url = validate_url(url)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Fetching headers..."),
        transient=True
    ) as progress:
        progress.add_task("fetch", total=None)
        redirect_chain = fetch_headers(url, follow_redirects)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Analyzing headers..."),
        transient=True
    ) as progress:
        progress.add_task("analyze", total=None)
        results = analyze_headers(redirect_chain)
    
    display_results(url, redirect_chain, results)

def interactive_mode():
    """Run the tool in interactive mode."""
    console.print(Panel("[bold]Security Headers Checker - Interactive Mode[/bold]", expand=False))
    
    while True:
        url = console.input("[bold]Enter URL to check (or 'q' to quit): [/bold]")
        
        if url.lower() in ('q', 'quit', 'exit'):
            break
        
        try:
            url = validate_url(url)
            follow_redirects = typer.confirm("Follow redirects?", default=True)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Fetching headers..."),
                transient=True
            ) as progress:
                progress.add_task("fetch", total=None)
                redirect_chain = fetch_headers(url, follow_redirects)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Analyzing headers..."),
                transient=True
            ) as progress:
                progress.add_task("analyze", total=None)
                results = analyze_headers(redirect_chain)
            
            display_results(url, redirect_chain, results)
            
            console.print("\n")
            
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")

@app.command()
def interactive():
    """Run the tool in interactive mode."""
    interactive_mode()

if __name__ == "__main__":
    console.print(Panel.fit(
        "[bold cyan]Security Headers Checker[/bold cyan]\n"
        "A CLI tool to detect missing or misconfigured security headers",
        border_style="cyan"
    ))
    app.callback()(lambda: None)
    app()
