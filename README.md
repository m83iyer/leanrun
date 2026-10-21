# leanrun: small, opt-in Codex efficiency starter

An independently authored starter, not an official OpenAI product or endorsement.

A Python standard-library wrapper for safe, local, read-only checks. Three concrete controls: content-keyed successful-evidence reuse, single-owner task claims, and bounded log output. This is **not a native Codex hook**, global quota manager, security sandbox, automatic agent interceptor, or promise of zero wasted tokens. It only affects commands explicitly routed through it.

## One-prompt setup with Codex

Download this repository (Code → Download ZIP), extract it in your Linux environment, and give Codex the kit plus the prompt in [ADOPT_WITH_CODEX.txt](ADOPT_WITH_CODEX.txt). The prompt asks Codex to inspect your existing repository, verify the fixture, and configure one appropriate check only when its declared inputs cover the dependencies. It does not enable global interception or claim measured savings. Review the proposed command and coverage before relying on reuse.

## Requirements and installation

Python 3.9 or newer; Linux; a local filesystem with working POSIX `flock`. No pip packages, account, API, network access or paid usage are needed by this kit. Tested on Linux only. macOS is not verified; Windows is unsupported. Do not use on Windows or a network filesystem.

Unpack this folder somewhere private. In a terminal, change into the unpacked folder. Nothing installs globally and no Codex configuration is changed.

```sh
python3 --version
python3 -m unittest -v
python3 leanrun.py run --task demo --root demo --scope unit --input inputs.json --env environment.json --file check.py -- python3 check.py
python3 leanrun.py run --task demo --root demo --scope unit --input inputs.json --env environment.json --file check.py -- python3 check.py
```

The first run reports `"state": "passed", "reused": false`; the second reports `"reused": true` without starting the command again. Both return JSON containing the retained full-log path and its last at most 4096 bytes. The demonstration prints only `PASS: safe local demo`.

Prove invalidation by adding a harmless comment:

```sh
printf '\n# source changed\n' >> demo/check.py
python3 leanrun.py run --task demo --root demo --scope unit --input inputs.json --env environment.json --file check.py -- python3 check.py
```

It reports `"reused": false`. A changed file, scope, command, JSON descriptor, wrapper source, Python/platform description or absolute project root changes the evidence key. Content hashes, not modification times, drive reuse. Changes during the check fail the run rather than certify mixed inputs.

## Use with your own checks

Choose one stable task ID per work item, a private local state directory shared by all collaborating callers, and a read-only, deterministic check. Put a small `inputs.json` and `environment.json` in the project root. Both must be valid JSON; their contents are otherwise your schema. Example environment descriptor:

```json
{"runtime":"Python 3.12.7", "dependency_lock":"requirements.lock", "service_fixture":"local-v3"}
```

Then pass `--file` once for **every** source, test, fixture, configuration and lockfile the check depends on. Paths are relative to `--root`. Symlinks, absolute input paths and `..` traversal are rejected. Directories/globs are not expanded. Files that are not declared are not tracked. The program does not inspect imports or infer the dependency graph.

```sh
python3 /path/to/leanrun.py run --state /private/local/check-state --task parser-unit --root /path/to/project --scope parser-unit --input inputs.json --env environment.json --file parser.py --file test_parser.py --file requirements.lock -- python3 -m unittest test_parser
```

Replace those paths and filenames with your actual project. No real repository is included or modified by installation. Use absolute executable paths if PATH resolution could vary. Keep the environment descriptor current when runtimes, dependency versions, services or relevant environment values change. The wrapper deliberately does not read or record your environment variables or persist command arguments in plaintext. It hashes the command in the evidence key. **Do not put secrets in arguments, descriptors, source selections or command output.** This wrapper cannot recognize or redact secrets printed by a command: stdout and stderr are saved verbatim in a private log and the tail is returned. Do not send those logs to an agent without checking their contents.

A useful Codex instruction, after you have reviewed your check's input coverage:

> For this named check, use the leanrun command shown above. Reuse only a passed result returned by that command. Do not replace it with an unwrapped duplicate run. If blocked, report why rather than changing the task ID or state directory.

This instruction does not itself enforce agent behavior. The backend checks are enforceable only on cooperating calls using the same state path and task ID.

## What the result actually proves

A reused result means: the prior routed command exited zero; declared content, scope, invocation and runtime description still match; and the saved log still matches its stored SHA-256. It does not prove tests were sufficient, independently reviewed, fresh against a changing remote service, or free of flaky behavior. It does not restore output artifacts. Use it for deterministic validation/evidence, not builds whose outputs must exist, deployments, payments, writes or commands that must run every time.

Changes to undeclared files, inherited environment variables, executable contents, package installations, remote data or an input changed and restored between snapshots can escape detection. Add appropriate declared dependencies, update descriptors, or explicitly release evidence before rerunning. This is a practical cache with explicit inputs, not a hermetic build system or tamper-proof certificate. A malicious process with your user account can alter state.

## Claims, failure, and recovery

A nonblocking OS lock atomically admits one cooperating owner for a task. A concurrent caller or release returns exit 2 without starting a command. A failure or timeout produces `failed` evidence, never a reusable pass. Default timeout: 300 seconds; `--timeout` accepts 0 < seconds <= 86400. Exit codes: 0 = passed/reused or released; 1 = command/check failed; 2 = invalid or blocked request.

An abrupt wrapper crash can leave a `running` record. There is **no age-based automatic stealing**. Inspect the retained log and confirm the original command and any descendants have stopped before release:

```sh
python3 leanrun.py release --task demo
```

Use the same `--state` if you supplied a custom directory. Release refuses while another wrapper holds the lock. It archives prior evidence and invalidates reuse without deleting logs. Normal later runs also archive preceding evidence. A wrapper crash can leave child processes alive, and timeout kills the direct command, not necessarily grandchildren. Do not release while those remain active. This kit is not a process supervisor. A malformed evidence record fails closed; preserve it for inspection, then move the task directory aside manually only after confirming no active owner, rather than blindly deleting it.

## Logs, limits, and removal

State defaults to `.leanrun` under your current terminal directory. Directories must be owned by you with mode 0700; generated records and logs are mode 0600. Full logs are retained locally; only the final 4096 raw log bytes are decoded for the returned tail to reduce context ingestion. Invalid UTF-8 replacement and JSON escaping can make the serialized response larger than 4096 bytes. This bounds the source bytes selected for the tail, not token use, execution cost, disk usage, command network access or permissions. Long logs still consume disk. No log rotation or automatic deletion occurs.

To uninstall, stop all routed commands first, preserve any evidence/logs you need, then move this kit folder and its `.leanrun` directory to your system Trash. If you chose an external `--state`, move that directory to Trash separately only if it belongs exclusively to this kit. There are no background services or global configuration changes to undo.

## Test coverage

`python3 -m unittest -v` checks reuse/invalidation, failed results, in-flight input changes, symlinks/traversal, invalid JSON/corrupt evidence, log integrity, bounded tails/full preservation, single-owner concurrency and release refusal, explicit interrupted-run recovery, timeout, private state permissions and no shell expansion. The included suite contains 14 tests, verified on Linux. These are implementation tests, not an independent security audit.
