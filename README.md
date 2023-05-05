# SSH-VPN

Simple tool to automate the creation of an SSH tunnel for VPN-like purposes.

## Requirements

1. Remote end of tunnel must support root login (most distro's default to root with RSA).
1. Remote end has __public__ key in /root/.ssh/authorized_keys
1. Remote end is running a Linux distribution (ie script won't work with OpenSSH on Windows)
1. Local end has access to __private__ key.
1. Local end has ability to EUID 0 (either root access or sudo)
1. Local end is running a Linux distribution (ie script won't work with OpenSSH on Windows)

## To-Do

1. Allow for auxiliary SSH options to be passed to program
