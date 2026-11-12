"""
aesmodes.web - the visual learning app.

Start it with:   python -m aesmodes.web
It opens http://127.0.0.1:8455 in your browser.
"""

from .server import create_app

__all__ = ["create_app"]
