""" import os
import sys
import anthropic

api_key = os.getenv("ANTHROPIC_API_KEY")
if not api_key:
    raise SystemExit("Missing ANTHROPIC_API_KEY. Set it with: export ANTHROPIC_API_KEY='sk-ant-...'")

client = anthropic.Anthropic(api_key=api_key)

prompt = " ".join(sys.argv[1:]) or "Say hello from Codespaces"

resp = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=300,
    messages=[{"role": "user", "content": prompt}],
)

print(resp.content[0].text) """

import os
import sys
import anthropic

api_key = os.getenv("ANTHROPIC_API_KEY")
client = anthropic.Anthropic(api_key=api_key)

# Load your paper once
with open("Paper.pdf", "rb") as f:
    paper_bytes = f.read()

prompt = " ".join(sys.argv[1:])

resp = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=800,
    messages=[
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "This is my KEVGraph research paper. Understand it deeply and reason from it."
                },
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": paper_bytes
                    }
                },
                {
                    "type": "text",
                    "text": prompt
                }
            ]
        }
    ],
)

print(resp.content[0].text)