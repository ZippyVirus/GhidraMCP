# Project-control validation

Tested on Windows with Ghidra 12.1.4 and Java 21, 2026-10-19.

## Automated checks

- The Java extension compiles against the installed Ghidra SDK.
- Final combined Python, real Java HTTP and headless-Ghidra suite: 56 passed, one skipped.
  The skipped stdio subprocess test is explicitly POSIX-only. Headless fixtures
  cover ELF/PE loading, inspection, decompilation, byte reads, annotation and
  loopback/Origin/Host protections.
- The included real Java HTTP concurrency regression passed. Eight normal
  requests were held behind a deliberately blocked operation while a job-status
  request still completed. All normal requests completed after release.
- New Python tests cover capability negotiation, compatibility with older GUI
  backends, project identity, batched byte transport, script argument preservation,
  and error propagation. They are included in the 56-test result above.

The GUI controls are not advertised by headless providers. No GUI controls have
been claimed tested by the headless fixtures.

## Live GUI checks

- Listed/opened all seven programs in an existing MIPS project using MCP.
- Rejected a wrong project name before writing.
- Rejected a two-edit batch with an incorrect second expected value; a reread
  confirmed the earlier valid entry remained unchanged.
- Saved program edits explicitly and ran registered project export/build scripts
  through the GUI project. Build completion and the built artifact were checked
  separately from the initial asynchronous start response. A rebuild after
  analysis matched the previously published disc image byte for byte.
- Analyzed and saved all seven programs, comparing every initialized imported
  byte before and after. The game bytes were unchanged. One executable went
  from two explicitly defined functions to 743 identified functions. Existing
  analysis was preserved. This is evidence from that project, not a promise
  that every analyzer in every program leaves bytes unchanged.
- Reproduced and fixed a save-timing race at the end of analysis. The final live
  check returned `ready_to_save: true`, followed immediately by a successful save.
- Started a harmless registered script that displayed a modal dialog. MCP read
  its title, full message, current ID and enabled OK button; submitted that exact
  response; then observed the script job finish with its expected output.
- The GUI checks exposed a missing multiline-label text case, which was fixed
  and retested. Dialog text covers Swing labels/editor panes and Ghidra's
  `MultiLineLabel`; arbitrary custom-painted widgets remain a limitation.

The initial analysis run, save race and incomplete dialog-text read were
development failures, not passes. No proprietary binaries or Ghidra project
databases are included in this branch.
