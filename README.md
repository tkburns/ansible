# Ansible Playbooks for Personal Use

This has ansible playbooks for setting up a computer for personal, day-to-day use.
It contains playbooks for setting up Windows, Linux, and WSL.

## Installation

This repos is setup with playbooks for a couple of different systems: Windows, WSL, and Linux.

### Windows

1. Enable PowerShell Scripts
    ```pwsh
    $ Set-ExecutionPolicy Bypass -Scope CurrentUser
    ```

2. Source the Ansible commands
    ```pwsh
    $ Invoke-Expression (Invoke-WebRequest _).Content
    ```

3. Setup the Ansible pre-reqs
    ```pwsh
    $ Install-Ansible
    ```

4. Run the playbook
    ```pwsh
    $ ansible pull _ 
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


