# UltraViolet

Purple-team CLI session recorder. Wraps a PowerShell REPL, executes what you type,
and journals every command with the metadata a blue team needs to correlate your
activity against CloudTrail, Azure Activity Log and Entra sign-in logs.

Zero dependencies — no `ImportExcel`, no Excel install, no pip. The XLSX writer is
a built-in OOXML generator.

---

## Run

From `cmd.exe`:

```
UltraViolet.cmd
```

From PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\UltraViolet.ps1
# optional
.\UltraViolet.ps1 -DataRoot 'D:\Engagements\ACME\sessions'
.\UltraViolet.ps1 -NoTheme
```

No flags are required — everything is in the menu.

**Requirements:** Windows, PowerShell 5.1 or 7.x. `Get-NetTCPConnection` (Win8/2012+)
is used for connection sampling; the tool falls back to `netstat -ano` if absent.

---

## Recognising a recorded window

The console repaints to `#A100FF` with white text and the title becomes
`[ULTRA-VIOLET] UltraViolet 1.3.0 - REC: <session>`. Every prompt is prefixed
`[UV <session>] <cwd>` (`[UV PAUSED <session>] <cwd>` while `:pause` is active).

- **Windows Terminal / PowerShell 7** — exact `#A100FF` via VT truecolor.
- **Legacy conhost** — the tool remaps palette slot 5 (`DarkMagenta`) to
  `#A100FF` via `SetConsoleScreenBufferInfoEx`, so the colour is still exact.
- `-NoTheme` disables all of it.

---

## Menu

```
1) Create New Session   -> name -> [optional egress-IP lookup] -> Continue to session? Y/N
2) Resume Session       -> pick -> re-enters the REPL, appends to the same files
3) Edit Session         -> pick -> view / edit / delete rows, export or re-import XLSX
4) Delete Session       -> pick -> Are you sure? + type the session name to confirm
5) Exit                 -> Are you sure?
```

## Inside a session

`exit session` returns to the main menu. Everything else you type is executed and recorded.

| Meta-command | Effect |
|---|---|
| `:help` | Command list |
| `:intent <text>` | Sticky intention applied to subsequent commands |
| `:intent` | Clear it — auto-classification resumes |
| `:note <text>` | Append a note to the last row |
| `:api <text>` | Override `API Used` on the last row |
| `:fix <Field> <value>` | Override any editable field on the last row |
| `:last [n]` | Show the last n rows |
| `:variables` | Table of every variable assigned this session |
| `:variables <name>` | One variable in full, read from the live shell |
| `:raw <command>` | Run with a real console — for interactive prompts and TUIs |
| `:sync` | Re-render the XLSX now |
| `:pause` / `:resume` | Execute without recording / resume |
| `:auth` | Re-read local AWS/Azure auth context |
| `:info` | Paths and counters |

Commands run **in-process**, so `cd`, `$env:AWS_PROFILE = ...`, variables and
loaded modules persist across the session exactly as in a normal shell.

An unfinished command — open block, quote, here-string, trailing pipe or
backtick — keeps prompting with `>>` until it parses as a complete statement. An
empty line abandons the continuation. A genuine syntax error that is *not*
incomplete is executed anyway, so the failure gets recorded instead of trapping
you in a continuation loop.

Arrow-key history, Home/End, Ctrl+U and Ctrl+C (clear line) are supported. The
line you are typing renders bold in `#FFC400`; change `$script:InputRgb` near the
top of the script to retune it.

Commands that prompt or paint a TUI (`ssh`, `vim`, `less`, a bare `python`/`node`
REPL, `aws configure`, `Enter-PSSession`, ...) are auto-detected and given the real
console, because piping their output through `Out-String` buffers the prompt and
they look hung. Prefix anything else with `:raw` to force it. Passthrough rows
still record the command, exit code, timing, network and API — only `Output` is
uncaptured, and `Notes` says so.

---

## Variable memory

Assignments persist across commands and are journalled. `$TOKEN = "..."` on one
line is usable on the next, and shows up in `:variables` with its type, length,
which row set it, and the command that set it.

This needed a fix, not just a feature: commands are dot-sourced inside the
recorder function, so anything they assigned died with that function's scope and
never reached the next prompt. New variables are now promoted to global after
each command. PowerShell's automatic and read-only variables (`$Host`, `$Error`,
`$PWD`, the `*Preference` set, ...) are never promoted. `$global:`/`$script:`
assignments and `$env:NAME = ...` writes are picked out of the command text,
since those never appear as new locals.

```
:variables            table of everything assigned
:variables TOKEN      one variable in full
```

State lives in `variables.json` in the session folder and is restored when you
resume — scalars (string, int, bool, decimal) go back into the shell; anything
richer is recorded but reported as not restorable, because faithfully rehydrating
an arbitrary object from JSON is not something to guess at silently.

**Credential-shaped names are masked on disk.** If a name matches
`pass|pwd|secret|token|cred|key|bearer|auth|sas|signature|connstr|private|session`,
its value is never written to `variables.json` or the workbook — only its length.
`:variables <name>` still reveals it, because it reads the live shell rather than
the file. Those variables are also not restorable on resume, by design. The
command that set them is still in the `Command` column, so this reduces exposure
rather than eliminating it.

---

## Files

One directory per session — the data root stays a clean list of folders:

```
<DataRoot>\
    2026-08-23 13-26-51 - template\
        session.meta.json                        session metadata
        session.jsonl                            write-ahead journal (source of truth)
        variables.json                           variable memory
        2026-08-23 13-26-51 - template.xlsx          rendered workbook
        outputs\                                 full output for rows > 30k chars
    2026-08-23 13-35-47 - template2\
        ...
```

Default `DataRoot` is `%USERPROFILE%\Documents\UltraViolet\Sessions`.

A folder counts as a session if it contains `session.meta.json`, `session.jsonl`
or any `.xlsx`. If the meta file is missing or corrupt it is rebuilt from the
folder name and the journal rather than the session being dropped, and the next
row ID is recovered by scanning the journal. If a folder is still skipped, the
main menu prints the folder and the reason.

Sessions written by 1.0.x as flat sibling files are migrated into folders
automatically the first time the menu enumerates them; stray Excel lock files
(`~$....xlsx`) and `.tmp` renders are cleaned up in the same pass. Discovery now
enumerates directories and reads `session.meta.json`, so a session is found as
long as its folder is present.

The JSONL is flushed **after every command**, so a crash or a dropped RDP session
costs at most the in-flight command. The XLSX is re-rendered from the journal
after every command, on `:sync`, and on session exit — so the workbook never lags
the journal. If the workbook is locked (open in Excel) you get one warning, the
journal keeps recording, and `:sync` catches the workbook up once you close it. That means the XLSX is always
appendable and always regenerable — if Excel has it open and locks it, the render
is left at `<name>.xlsx.tmp` and you are told.

Edit Session also offers `E` to drop every row marked `Error` in one go, and `V`
to view that session's recorded variables. Think before using `E`: a denied API
call is evidence that a control held, and is often the most useful row in the
report.

If you edit the workbook directly in Excel, use **Edit Session → `I`** to pull those
edits back into the journal (matched by the `#` column). Truncated `Output` cells
are skipped on import so you cannot lose the full text.

---

## Recorded fields

Sheet `Session`:

| Column | Source |
|---|---|
| `#` | Monotonic row ID |
| `Local Time` / `UTC Time` | Command start, `DD/MM/YY hh:mm:ss` |
| `Command` | Exact line as typed |
| `Result` | `Success` / `Error` |
| `Reason` | Extracted AWS `An error occurred (Code)`, Azure `ERROR:` / `AADSTS`, JSON `Code`/`Message`, PS exception, or exit-code summary |
| | Native **stderr** writes are *not* failures — see below |
| `Output` | Full stdout+stderr, ANSI stripped |
| `Source IP` | Public egress IP (if looked up) and/or local interface IP |
| `Source Port` | Ephemeral port of the sampled connection |
| `Destination IP` / `Destination Port` | Sampled, or DNS-resolved from the derived service endpoint |
| `Logon Type` | `Win32_LogonSession.LogonType` for this process, e.g. `10 (RemoteInteractive)` |
| `API Used` | Derived, e.g. `ec2:DescribeInstances`, `az keyvault secret show [Microsoft.KeyVault]` |
| `Intention` | Sticky value if set, otherwise auto-classified |
| `Cloud` | AWS / Azure / GCP / Kubernetes / Local |
| `Principal`, `Auth Type` | Local config inspection (profile, SSO, session token, Entra user vs SPN, MI endpoint) |
| `ATT&CK` | Mapped tactic/technique, e.g. `TA0006 Credential Access / T1552.005` |
| `Exit Code`, `Duration (ms)`, `Host`, `OS User`, `Output File`, `Notes` | Context |

Sheet `Variables` carries the variable memory: name, type, length, value,
change count, first/last set, the row that set it, sensitivity, restorability and
the command. Sheet `Session Info` carries session metadata and render timestamps.

Error rows are shaded; the header is `#A100FF`; the top row is frozen with autofilter on.

---

## How the derived fields actually work — and where they are soft

**Network 4-tuple.** A background runspace polls established TCP connections every
120 ms during command execution and diffs against a pre-command baseline, then
prefers new public-destination connections on 443/80 owned by `aws`/`az`/`python`/
`pwsh`/`curl`/`kubectl`. Short-lived or connection-pooled requests can be missed;
in that case the destination is DNS-resolved from the endpoint derived from the
command (`ec2.eu-west-1.amazonaws.com`, `management.azure.com`,
`graph.microsoft.com`) and the source IP from `Find-NetRoute`. Rows resolved this
way say so in `Notes`. If multiple egress connections were seen, `Notes` records
the count.

**Output capture.** Every `ErrorRecord` is reduced to its message before it
reaches `Out-String`. Without that, one stderr line from `aws`, `node` or `git`
is rendered as a multi-line `At line:1 char:5 / + CategoryInfo ...` block, which
both pollutes the `Output` column and trips the error scan. Output is written to
the journal only once the command's pipeline has fully drained, so progressive
output is recorded whole.

**Success vs Error.** PowerShell wraps every native stderr write in a
`NativeCommandError` record and clears `$?`, so any tool that logs progress or
warnings to stderr — `node`, `aws-azure-login`, `terraform`, `git` — would be
scored as a failure on a perfectly good run. Those records are filtered out; the
verdict comes from the exit code, real PowerShell exceptions, and cloud error
signatures found in **stderr**. A signature in stdout can only enrich the reason
for an already-failed command, never raise one — otherwise `aws logs tail` on a
log stream containing the word ERROR would be scored as a failure. Suppressed stderr writes are counted in `Notes`.

**API mapping** is a parser, not the wire. AWS is `service` + kebab→Pascal
operation. Azure is the command path plus an ARM provider lookup. Anything the
mapper gets wrong is fixable with `:api` or in Edit Session. If you need
authoritative operation names, `aws --debug` output will be captured in `Output`
verbatim.

**Source IP for log correlation.** CloudTrail `sourceIPAddress` and Entra sign-in
logs record your **public egress IP**, not the interface IP. Enable the egress
lookup at session creation to have both in the `Source IP` column. It is off by
default because it makes one outbound request to a third-party IP-echo service —
skip it in environments where that is not acceptable and fill the value manually.

**Auth context** is read from `%USERPROFILE%\.aws\config` / `.credentials` and
`.azure\azureProfile.json` plus environment variables. No network calls, no token
reads, nothing written.

---

## Scope

The tool records what you type. It performs no scanning, no credential access and
generates no traffic of its own beyond the optional egress-IP lookup. Session files
contain full command output, which will include whatever your commands returned —
treat them as engagement evidence and handle them accordingly.
