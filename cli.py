# /cli.py
import click
import json
import os
from urllib.parse import urlparse

# --- Import the main functions from each module ---
from DAST.main_controller.dast_cli import run_dast
from SAST_check import sast_scan_directory
from correlation_engine import run_correlated_scan

@click.group()
def cli():
    """A SAST, DAST, and SAST+DAST correlation scanner."""
    pass

@cli.command('sast')
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def sast_command(path: str):
    """
    Run a standalone SAST scan on a source code directory.
    """
    absolute_path = os.path.abspath(path)
    click.secho(f"[*] Running SAST scan on: {absolute_path}", fg='cyan')
    sast_findings = sast_scan_directory(absolute_path)
    
    click.secho("\n--- SAST Scan Report ---", bold=True)
    if sast_findings:
        print(json.dumps(sast_findings, indent=2))
        click.secho(f"\n[+] Found {len(sast_findings)} potential vulnerabilities.", fg='yellow')
    else:
        click.secho("[+] No potential web vulnerabilities found.", fg='green')

@cli.command('dast')
@click.argument('url')
def dast_command(url: str):
    """
    Run a standalone DAST scan (crawl and attack) on a live URL.
    """
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        click.secho("Error: Invalid URL. Please include http/https (e.g., http://127.0.0.1:5000).", fg='red')
        raise click.Abort()

    click.secho(f"[*] Running DAST scan on: {url}", fg='cyan')
    dast_findings = run_dast(url)

    click.secho("\n--- DAST Scan Report ---", bold=True)
    if dast_findings:
        # DAST output is already printed by the run_dast function,
        # but we can add a summary here.
        click.secho(f"\n[+] DAST scan complete. Found {len(dast_findings)} vulnerabilities.", fg='red', bold=True)
    else:
        click.secho("\n[+] DAST scan complete. No vulnerabilities found.", fg='green')

@cli.command('full-scan')
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
@click.argument('url')
def full_scan_command(path: str, url: str):
    """
    Run the correlated SAST+DAST scan for high-confidence results.
    """
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        click.secho("Error: Invalid URL. Please include http/https (e.g., http://127.0.0.1:5000).", fg='red')
        raise click.Abort()

    absolute_path = os.path.abspath(path)
    click.secho("[*] Starting Correlated SAST + DAST Scan", fg='cyan', bold=True)
    click.secho(f"    - SAST Path: {absolute_path}", fg='cyan')
    click.secho(f"    - DAST URL:  {url}", fg='cyan')

    confirmed_vulns = run_correlated_scan(absolute_path, url)

    click.secho("\n--- ✅ Correlated Scan Report ---", bold=True)
    if confirmed_vulns:
        click.secho(f"🎉 Found {len(confirmed_vulns)} confirmed vulnerabilities:", fg='red', bold=True)
        print(json.dumps(confirmed_vulns, indent=2))
    else:
        click.secho("✅ No SAST findings could be confirmed by DAST.", fg='green')

if __name__ == '__main__':
    cli()