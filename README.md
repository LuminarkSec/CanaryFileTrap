# CanaryFileTrap - multiple canary files and configurable content

Creates one or more canary files, writes configurable dummy data into them, applies a read-audit SACL, subscribes to Windows Security Event ID `4663`, and reports the process that accessed any canary.

It can optionally suspend and/or dump the accessing process.

## Audit policy check

Read detection depends on Windows Security Auditing.

Check status:

```bat
CanaryFileTrap.exe --check-audit-policy
```

Enable if needed:

```bat
CanaryFileTrap.exe --enable-audit-policy
```

## Creating canary content

Default behaviour creates one 4 KiB random-text canary under:

```text
%ProgramData%\CanaryTrap\canary.txt
```

Create a larger random-text canary:

```bat
CanaryFileTrap.exe --size 128K --data-mode text --enable-audit-policy
```

Create a random binary canary:

```bat
CanaryFileTrap.exe --size 1M --data-mode binary
```

Create fixed repeated content:

```bat
CanaryFileTrap.exe --size 64K --content "Payroll backup credentials - confidential"
```

`--size` accepts bytes, `K`, `M`, or `G`, up to 1 GiB.

## Multiple files

Repeat `--path`:

```bat
CanaryFileTrap.exe --path C:\Users\Public\Documents\invoice_passwords.txt --path C:\Users\Public\Documents\hr_backup.txt --size 64K --data-mode text
```

Generate multiple files in a directory:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 10 --prefix backup_passwords --extension .txt --size 128K --data-mode text
```

Read paths from a file:

```bat
CanaryFileTrap.exe --path-list canaries.txt --size 256K --data-mode binary
```

`canaries.txt` format:

```text
# comments are allowed
C:\Users\Public\Documents\invoice_passwords.txt
C:\Users\Public\Documents\finance_export.csv
```

## Actions

Report only:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 5
```

Suspend the accessing process:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 5 --suspend
```

Dump the accessing process:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 5 --dump --dump-dir C:\Dumps
```

Full memory dump:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 5 --dump --full-dump --dump-dir C:\Dumps
```

## Default exclusions

Excluded by default:

```text
explorer.exe
CanaryFileTrap.exe itself
```

Add more exclusions:

```bat
CanaryFileTrap.exe --exclude-name notepad.exe,backup.exe
```

Actions are performed once per PID by default. Use `--repeat-actions` to allow repeated suspend/dump actions for the same PID.

## Notes

- Run elevated.
- File read detection is based on Security Auditing and Event ID 4663, not a kernel minifilter driver.
- If no events appear, run `--check-audit-policy`, then `--enable-audit-policy`, and confirm the canary files have Auditing entries.
- Use `--suspend` carefully; broad use can disrupt legitimate software.

## Help

```bat
CanaryFileTrap.exe --help
```

The help output lists all supported options.

## Cleanup

Canary files are left in place by default. To delete them after a clean Ctrl-C shutdown:

```bat
CanaryFileTrap.exe --dir C:\Users\Public\Documents --count 5 --cleanup-on-exit
```

This only runs during a clean shutdown. It will not clean up after a crash, forced kill, or reboot.
