# Publication checks

Date: 2026-09-17

- Source: current files in the MANTIS development workspace.
- Destination: Anuskar123/mantis1, main branch.
- Publishing copy prepared separately; original working files and staged changes were left intact.
- Python: 3.14.6 on Windows.
- Regression suite: 119 tests passed.
- Synthetic replay: generated and processed 13,159 packets successfully.
- Five-engine training: exercised using the packaged Stage 1 training files.
- Credential-pattern scan: no matching GitHub tokens, OpenAI project keys, AWS access key IDs, or private-key headers detected in the publishing files, including Office XML. This is a pattern scan, not a guarantee that every form of sensitive content is absent.
- All 82 copied academic deliverables matched their source SHA-256 hashes.
- No published file reaches GitHub's 100 MiB individual Git file limit.

The automated suite includes three dataset-stage checks in addition to the earlier 116-test suite. Existing 116-test screenshots are historical evidence and have not been relabelled.

Live Linux capture, firewall effects, full external-corpus benchmarks, and Office rendering were not rerun for publication. Existing DOCX, PDF, PPTX, XLSX, and diagram artifacts were copied without content edits.

## Excluded local material

Raw dataset archives and multipart binaries, extracted raw CSV collection, virtual environments, generated model states, live packet captures and logs, temporary files, backup copies, university handouts, and duplicate packaged source archives remain outside this Git repository. Processed CSV exports, small training samples, split manifests, raw archive metadata, and reconstruction scripts are included.
