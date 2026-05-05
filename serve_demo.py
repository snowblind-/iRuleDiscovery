#!/usr/bin/env python3
"""
Serve irule_output/ on http://localhost:8765 for screenshot capture.
Run: python3 serve_demo.py
Then open: http://localhost:8765/irule_viewer.html
Stop with Ctrl-C.
"""
import http.server
import os

os.chdir(os.path.join(os.path.dirname(__file__), "irule_output"))
server = http.server.HTTPServer(("127.0.0.1", 8765), http.server.SimpleHTTPRequestHandler)
print("Serving http://localhost:8765/irule_viewer.html")
print("Stop with Ctrl-C")
server.serve_forever()
