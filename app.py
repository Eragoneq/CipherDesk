"""Windows/PyInstaller entry point for CipherDesk."""

import sys

from cipherdesk.ui import main


if __name__ == "__main__":
    sys.exit(main())
