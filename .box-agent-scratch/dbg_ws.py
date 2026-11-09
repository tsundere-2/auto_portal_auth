import subprocess, sys, tempfile, time, json
sys.path.insert(0, r"D:\auto_portal_auth")
import cdp_client as cdp

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = 19225
prof = tempfile.mkdtemp(prefix="cdpdbg-")

p = subprocess.Popen([EDGE, f"--remote-debugging-port={PORT}", "--headless=new",
                      f"--user-data-dir={prof}", "--no-first-run", "about:blank"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    assert cdp.wait_port(PORT, 20), "port not ready"
    pages = [t for t in cdp.list_targets(PORT) if t.get("type") == "page"]
    url = pages[0]["webSocketDebuggerUrl"]
    print("connecting:", url)

    ws = cdp._WS(url, timeout=8)
    print("handshake done")

    ws.send(json.dumps({"id": 1, "method": "Browser.getVersion", "params": {}}))
    print("sent, waiting...")
    for i in range(3):
        try:
            raw = ws.recv()
            print(f"recv[{i}]:", raw[:300])
            break
        except Exception as e:
            print(f"recv[{i}] error: {type(e).__name__} {e}")
            break
    ws.close()
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    p.terminate()
    time.sleep(1)
    p.kill()
