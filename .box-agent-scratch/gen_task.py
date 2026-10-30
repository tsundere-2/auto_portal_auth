import sys
from pathlib import Path

sys.path.insert(0, r"D:\auto_portal_auth")
import auto_portal_auth as app

exe = r"C:\Users\14976\AppData\Local\Programs\Python\Python312\pythonw.exe"
script = r"D:\auto_portal_auth\auto_portal_auth.py"
command = f'"{exe}" "{script}"'
xml = app._watchdog_xml(command, r"D:\auto_portal_auth", 5)

out = Path(r"D:\auto_portal_auth\.box-agent-scratch\wd.xml")
out.write_text(xml, encoding="utf-16")
print("written:", out, out.stat().st_size, "bytes")

import xml.etree.ElementTree as ET

root = ET.parse(out).getroot()
ns = {"n": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
print("triggers:", [x.tag.split("}")[1] for x in root.findall(".//n:Triggers/*", ns)])
print("command :", root.find(".//n:Actions/n:Exec/n:Command", ns).text)
print("args    :", root.find(".//n:Actions/n:Exec/n:Arguments", ns).text)
print("workdir :", root.find(".//n:Actions/n:Exec/n:WorkingDirectory", ns).text)
print("user    :", root.find(".//n:Principal/n:UserId", ns).text)
