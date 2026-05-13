"""wpf — Web Pentest Framework.

Authorization-gated, data-driven, modular. Wraps best-of-breed Kali tools to run
the full OWASP WSTG v4.2 checklist and Vickie Li's Bug Bounty Bootcamp workflows.
"""

__version__ = "0.1.0"

BANNER = r"""
        __        ______  _____
       / /       /  __  \|  ___|
   ___| |    ___ | |  | || |_
  / _ \ |   / _ \| |  | ||  _|
 |  __/ |__|  __/| |__| || |
  \___|____\___|  \____/ |_|
       w  p  f   v{version}
   Web Pentest Framework — WSTG v4.2 + Bug Bounty Bootcamp + ars0n recon
""".format(version=__version__)
