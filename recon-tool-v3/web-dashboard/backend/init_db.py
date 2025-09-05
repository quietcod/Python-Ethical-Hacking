"""
Database initialization script
Phase 6 - Web Dashboard Backend
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from app.core.database import init_db

if __name__ == "__main__":
    print("🚀 Initializing Recon-Tool-v3 Web Dashboard Database...")
    init_db()
    print("✅ Database initialization complete!")
