"""
Run the learning app:   python -m aesmodes.web  [--port 8455] [--no-browser]
"""

import argparse
import threading
import webbrowser

from .server import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m aesmodes.web",
                                     description="AES modes of operation: visual learning app")
    parser.add_argument("--port", type=int, default=8455)
    parser.add_argument("--no-browser", action="store_true", help="don't open the browser")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    print(f"\n  AES learning app running at {url}\n  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    create_app().run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
