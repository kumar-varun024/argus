from argus.runtime.local import LocalRuntime
from argus.runtime.parser import ReconParser

rt = LocalRuntime()

result = rt.run_command(
    executable="katana",
    args=[
        "-u",
        "https://www.hackerone.com",
        "-silent",
    ],
)

print("Return code:", result["returncode"])

parsed = ReconParser.parse_katana(result["stdout"])

print("Raw lines:", len(result["stdout"].splitlines()))
print("Parsed endpoints:", len(parsed))
print("First 10 parsed:")

for endpoint in parsed[:10]:
    print(endpoint)
