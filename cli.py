# cli.py

import click
import json
from urllib.parse import urlparse

# Import your runner scripts
from sast_runner import run_sast
from dast_runner import run_dast
from correlation_engine import run_correlated_scan


@click.group()
def cli():
    """
    HackMeHarder: A lightweight SAST + DAST scanner with intelligent correlation.

    Available commands:
      - sast        Run a SAST-only scan on source code.
      - dast        Run a DAST-only scan on a running application.
      - full-scan   Run the full correlated SAST + DAST pipeline.

    Run 'security-scanner <command> --help' for details on each command.
    """
    pass


# --- Command 1: SAST Scan ---
@cli.command('sast')
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def sast_command(path: str):
    """Run a SAST-only scan on source code at PATH."""
    click.secho(f"[*] Running SAST scan on: {path}", fg='cyan')
    sast_findings = run_sast(path)

    click.secho("\n--- SAST Scan Report ---", bold=True)
    if sast_findings:
        print(json.dumps(sast_findings, indent=2))
        click.secho(f"\n[+] Found {len(sast_findings)} potential vulnerabilities.", fg='yellow')
    else:
        click.secho("[+] No vulnerabilities found.", fg='green')


# --- Command 2: DAST Scan ---
@cli.command('dast')
@click.argument('url')
def dast_command(url: str):
    """Run a DAST-only scan on a live web application at URL."""
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        click.secho("Error: Invalid URL. Please include http/https (e.g., http://127.0.0.1:5000).", fg='red')
        raise click.Abort()

    click.secho(f"[*] Running DAST scan on: {url}", fg='cyan')
    dast_findings = run_dast(url)

    click.secho("\n--- DAST Scan Report ---", bold=True)
    if dast_findings:
        print(json.dumps(dast_findings, indent=2))
        click.secho(f"\n[+] Found {len(dast_findings)} vulnerabilities.", fg='red')
    else:
        click.secho("[+] No vulnerabilities found.", fg='green')


# --- Command 3: Full Correlated Scan ---
@cli.command('full-scan')
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
@click.argument('url')
def full_scan_command(path: str, url: str):
    """Run the full correlated SAST + DAST scan."""
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        click.secho("Error: Invalid URL. Please include http/https (e.g., http://127.0.0.1:5000).", fg='red')
        raise click.Abort()

    click.secho("[*] Starting Correlated SAST + DAST Scan", fg='cyan')
    click.secho(f"    - SAST Path: {path}", fg='cyan')
    click.secho(f"    - DAST URL:  {url}", fg='cyan')

    confirmed_vulns = run_correlated_scan(path, url)

    click.secho("\n--- ✅ Correlated Scan Report ---", bold=True)
    if confirmed_vulns:
        click.secho(f"🎉 Found {len(confirmed_vulns)} confirmed vulnerabilities:", fg='red', bold=True)
        print(json.dumps(confirmed_vulns, indent=2))
    else:
        click.secho("✅ No vulnerabilities confirmed via correlation.", fg='green')


if __name__ == '__main__':
    cli()
