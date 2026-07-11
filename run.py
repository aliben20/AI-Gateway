import uvicorn
import os
import sys
import webbrowser
from threading import Timer

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))

    def open_browser():
        webbrowser.open(f"http://localhost:{port}")

    Timer(1.5, open_browser).start()

    print("=" * 50)
    print("  AI Gateway - Smart API Gateway")
    print("=" * 50)
    print(f"  Server: http://localhost:{port}")
    print("  Login:  admin / admin123")
    print("=" * 50)
    print("  Press Ctrl+C to stop")

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info"
    )
