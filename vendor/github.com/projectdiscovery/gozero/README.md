# gozero

gozero: the wannabe zero dependency [language-here] runtime for Go developers

## Isolation

### Windows

Native isolation on windows is supported only with the PRO version and is implemented via Windows Sandbox (which needs to be [activated](https://www.makeuseof.com/enable-set-up-windows-sandbox-windows-11/)).

### Darwin

OSX implements native isolation via the command `sandbox-exec`. The command line interface is marked as deprecated, but the system functionality is actively supported, and profiles are still used in well-known software like chrome, firefox.

### Linux

On Linux, the functionality is implemented with the default command `systemd-run`, which should be available on most systems and allow a vast fine-grained sandbox configuration via SecComp and EBPF


## Note:

Sandbox is not enabled by default and needs to be used manually through sdk