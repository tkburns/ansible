# Ansible Playbooks for Personal Use

This has ansible playbooks for setting up a computer for personal, day-to-day use.
It contains playbooks for setting up Windows, Linux, and WSL.

## Installation

This repos is setup with playbooks for a couple of different systems: Windows, WSL, and Linux.

### Windows

1. Source the Ansible commands
    ```pwsh
    $ Invoke-Expression (Invoke-WebRequest https://raw.githubusercontent.com/tkburns/ansible/main/windows/powershell/Import-AnsibleCommands.ps1).Content
    ```

2. Setup everything needed for Ansible to run (WSL, WinRM, Firewall rules, etc)
    ```pwsh
    $ Install-Ansible
    ```

3. Run the playbook
    ```pwsh
    $ Invoke-AnsiblePlaybook
    ```

> When running the playbook when ansible has already been installed, you may have to update the
> firewall rule (wsl uses a dynamic network interface an IP, which gets recreated when wsl is rebooted).
>
> ```pwsh
> Repair-AnsibleFirewallRule
> ```

### WSL

Coming soon!

### Linux

Coming soon!


