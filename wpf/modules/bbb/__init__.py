"""Bug Bounty Bootcamp chapter workflows — one runner per chapter."""
from . import _shared  # noqa: F401
from ._shared import REGISTRY, BBBWorkflow, ManualChapter  # noqa: F401
from . import (ch05_recon, ch06_xss, ch07_open_redirect, ch08_clickjacking,
               ch09_csrf, ch10_idor, ch11_sqli, ch13_ssrf, ch14_deser,
               ch15_xxe, ch16_ssti, ch20_takeover, ch21_info_disclosure,
               ch24_api, _autoload)  # noqa: F401
