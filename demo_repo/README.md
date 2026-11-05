# FileDesk (VULNIGO demo target)

**Intentionally vulnerable. Do not deploy.** A tiny file-inspection service used as the
prepared target for VULNIGO Lite battles. It contains two planted bugs in `filedesk/tools.py`:

- `file_size()` - command injection (CWE-78): the name is pasted into a `shell=True` command.
- `read_upload()` - path traversal (CWE-22): `../` in the name reads files outside `uploads/`.
