# Security Headers Checker

A comprehensive CLI tool to detect missing or misconfigured security headers in websites.

## Features

- Checks for all important security headers
- Follows redirects and scans the entire redirect chain
- Provides detailed descriptions for each header
- Uses visual risk indicators with color coding
- Flags misconfigured headers (like weak CSP policies)
- Provides recommendations for fixing issues
- Calculates an overall security grade
- Supports both direct URL input and interactive mode

## Security Headers Checked

- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection
- Cache-Control

## Installation

\`\`\`bash
# Clone the repository
git clone https://github.com/yourusername/security-headers-checker.git
cd security-headers-checker

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x security_headers_checker.py
\`\`\`

## Usage

### Direct URL Check

\`\`\`bash
# Basic usage
./security_headers_checker.py check https://example.com

# Disable redirect following
./security_headers_checker.py check https://example.com --no-follow-redirects
\`\`\`

### Interactive Mode

\`\`\`bash
# Start interactive mode
./security_headers_checker.py interactive

# Or just run without arguments
./security_headers_checker.py
\`\`\`

## Requirements

- Python 3.7+
- requests
- rich
- typer
- colorama

## License

MIT
