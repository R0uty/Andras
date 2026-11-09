# Real tool lists

These fixtures are unmodified `tools/list` results from the official MCP
reference servers, captured on 2026-11-08 with `scripts/capture-tools-list.py`
(npm packages run through `npx`, an empty working directory, placeholder tokens).
They contain only tool definitions: no call and no output. A fixture passes if
no tool is quarantined.

| Fixture | Package | Version | Tools |
| --- | --- | --- | ---: |
| `b-101` | `@modelcontextprotocol/server-filesystem` | 1.0.0 | 14 |
| `b-102` | `@modelcontextprotocol/server-memory` | 1.0.0 | 9 |
| `b-103` | `@modelcontextprotocol/server-everything` | 1.0.0 | 13 |
| `b-104` | `@modelcontextprotocol/server-sequential-thinking` | 1.0.0 | 1 |
| `b-105` | `@modelcontextprotocol/server-github` | 2025.4.8 | 26 |
| `b-106` | `@modelcontextprotocol/server-gitlab` | 2025.4.25 | 9 |
| `b-107` | `@modelcontextprotocol/server-slack` | 2025.4.25 | 8 |
| `b-108` | `@modelcontextprotocol/server-brave-search` | 0.6.2 | 2 |
| `b-109` | `@modelcontextprotocol/server-google-maps` | 0.6.2 | 7 |
| `b-110` | `@modelcontextprotocol/server-puppeteer` | 2025.5.12 | 7 |
| `b-111` | `@modelcontextprotocol/server-postgres` | 0.6.2 | 1 |
| `b-112` | `@modelcontextprotocol/server-aws-kb-retrieval` | 0.6.2 | 1 |

The tool names, descriptions and schemas are from
[modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers).
That project is moving from the MIT License to Apache-2.0: contributions whose
authors have agreed are Apache-2.0, and the rest remain MIT. Packages that state
`MIT` in their `package.json` are MIT. Copyright belongs to their authors.

Redis and EverArt were also tried and did not answer `initialize`, so they are
not included.
