Here is a complete README.md file for your project.

HackMeHarder
HackMeHarder is a lightweight, correlated SAST and DAST scanner for Python Flask applications, built during the Code Cortex 2.0 hackathon. It analyzes source code to find potential vulnerabilities and then launches targeted attacks against a live server to confirm them.

The tool combines "white-box" static analysis (SAST) with "black-box" dynamic analysis (DAST) to provide high-confidence results with low false positives.

Installation
You can install HackMeHarder directly from its GitHub repository using pip. Ensure you have Python and Git installed on your system.

Bash

pip install git+https://github.com/ved-bankeshwar/HackMeHarder.git@ved
Usage
The tool provides three main commands for security testing.

Standalone SAST Scan
Analyze a local source code directory for potential vulnerabilities. This method is fast and identifies the exact line of problematic code.

Command:

Bash

hackmeharder sast <path_to_source_code>
Example:

Bash

hackmeharder sast C:\Users\Prasad\Documents\GitHub\Test_hacking
Standalone DAST Scan
Run a crawl-and-attack scan against a live, running web application. This method tests the application from an attacker's perspective.

Command:

Bash

hackmeharder dast <live_application_url>
Example:

Bash

hackmeharder dast https://flask-vulnerable-app.onrender.com
Full Correlated Scan (Recommended)
This is the most powerful feature. It runs the full SAST+DAST pipeline, using the static analysis results to guide the dynamic attacks. This provides a final report of confirmed, exploitable vulnerabilities.

Command:

Bash

hackmeharder full-scan <path_to_source_code> <live_application_url>
Example:

Bash

hackmeharder full-scan C:\Users\Prasad\Documents\GitHub\Test_hacking https://flask-vulnerable-app.onrender.com






