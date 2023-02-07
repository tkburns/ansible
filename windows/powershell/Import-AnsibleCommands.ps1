# Requirements:
# - PowerShell >= 3.0
# - .NET >= 4.0
#
# Any modern windows desktop should meet the PowerShell & .NET
# requirements out of the box
#
# If you are running this by downloading it to a local file,
# enable running unsigned scripts via the following:
# > Set-ExecutionPolicy Bypass -Scope Process
# (wht -Scope Process it only affects the current process)

# TODO List
# - Use splatting for optional params
# - standardize API (use 'Protocol' param everywhere?)
# - add 'WhatIf' param

function Install-Ansible {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'WinRM',

        [Parameter(Mandatory=$false)]
        [string]$WSLDistro
    )

    ##########
    #
    # Prep
    #

    # install wsl
    if ($WSLDistro) {
        wsl --install $WSLDistro
    } else {
        wsl --install
    }

    if ($Protocol -in 'WinRM', 'All') {

        ##########
        #
        # Setup WinRM (PSRemoting)
        #

        Enable-PSRemoting

        # setup HTTPS listener
        $cert = New-SelfSignedCertificate -FriendlyName '(Ansible) WinRM' -DnsName 'ansible.windows' -Type SSLServerAuthentication
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = "HTTPS"; Address = "*" } -ValueSet @{ Hostname = 'ansible.windows'; CertificateThumbprint = $cert.Thumbprint }

        # setup firewall
        Disable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-NoScope'
        Disable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP'
        Add-AnsibleFirewallRule -Protocol 'WinRM'
    }

    if ($Protocol -in 'SSH', 'All') {

        ###########
        #
        # Setup SSH
        #

        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'

        $psLocation = (Get-Process -Id $pid).Path
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "$psLocation"

        # create firewall rule
        Disable-NetFirewallRule -DisplayName 'OpenSSH SSH Server Preview (sshd)'
        Add-AnsibleFirewallRule -Protocol 'SSH'
    
    }


    ###########
    #
    # Install Ansible on WSL (Ubuntu) for controlling windows
    #

    [string[]] $wslExtraArgs = @()
    if ($WSLDistro) {
        $wslExtraArgs += "-d", "$WSLDistro"
    }

    # install ansible
    wsl $wslExtraArgs -- `
      sudo apt install -y software-properties-common '&&' `
      sudo apt-add-repository --yes --update ppa:ansible/ansible '&&' `
      sudo apt install -y python3 python3-pip ansible

    # install ansible command completion
    wsl $wslExtraArgs -- `
      pip3 install argcomplete '&&' `
      activate-global-python-argcomplete --user

    # install winrm
    wsl $wslExtraArgs -- pip3 install pywinrm

}


# TODO - break into multiple functions (eg Remove-AnsibleFirewallRule)
#        and reduce params here (just protocol & severity (disable, clean, uninstall)? & distro & scope (list - firewall, protocol/connection, wsl/control, etc)?)
#        - also introduce Disable/Enable-Ansible functions??
function Uninstall-Ansible {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$CleanFirewall = $true,

        [Parameter(Mandatory=$false)]
        [switch]$DisableWinRM = $true,

        [Parameter(Mandatory=$false)]
        [switch]$CleanWinRM = $true,

        [Parameter(Mandatory=$false)]
        [switch]$UninstallSSH = $true,

        [Parameter(Mandatory=$false)]
        [switch]$CleanWSL,

        [Parameter(Mandatory=$false)]
        [switch]$RemoveWSL,

        [Parameter(Mandatory=$false)]
        [string]$WSLDistro
    )

    if ($CleanFirewall) {
        # delete firewall rules
        Remove-AnsibleFirewallRule
    }

    if ($CleanWinRM) {
        # delete WinRM listener
        $listener = Get-WSManInstance -ResourceURI 'winrm/config/listener' -SelectorSet @{ Transport = "HTTPS"; Address = "*" }
        if ($listener) {
            $listener | Remove-WSManInstance

            # delete ssl certificate
            Remove-Item -Path "Cert:\LocalMachine\My\$($listener.CertificateThumbprint)"
        }
    }

    if ($DisableWinRM) {
        # disable powershell remoting access
        Disable-PSRemoting

        # disable the winrm service
        Stop-Service winrm
        Set-Service -Name winrm -StartupType Disabled
    }

    if ($UninstallSSH) {
        Remove-WindowsCapability -Name OpenSSH.Server~~~~0.0.1.0
    }

    if ($RemoveWSL) {
        Repair-WslEncoding

        if ($WSLDistro -ne $null) {
            # unregister provided distro
            wsl --unregister $WSLDistro
        } else {
            # unregister default distro
            $DefaultDistroMatch = (wsl --list | Select-String '(.*) \(Default\)')
            if ($DefaultDistroMatch.Matches -ne $null) {
                wsl --unregister $DefaultDistroMatch.Matches.Groups[1].Value
            } else {
                Write-Warning 'Unable to determine default WSL distro'
                Write-Warning 'Skipping removing WSL'
            }
        }
    } elseif ($CleanWSL) {
        [string[]] $wslExtraArgs = @()
        if ($WSLDistro) {
            $wslExtraArgs += "-d", "$WSLDistro"
        }

        # remove just ansible-specific things
        wsl $wslExtraArgs -- `
          pip3 uninstall pywinrm '&&' `
          sudo apt uninstall ansible '&&' `
          sudo apt-add-repository -r ppa:ansible/ansible
    }
}

function Invoke-AnsiblePlaybook {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH')]
        [string]$Protocol = 'WinRM',

        [PSCredential]$Credential,

        [string]$WSLDistro,

        [switch]$Check,
        [switch]$Diff,

        [string[]]$Tags,
        [string[]]$WSLPlaybookTags,

        [string[]]$ExtraArgs
    )

    # get credentials if not provided
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Enter your windows username/password" -UserName $env:UserName
    }

    # setup wsl args (distro)
    [string[]] $wslExtraArgs = @()
    if ($WSLDistro) {
        $wslExtraArgs += "-d", "$WSLDistro"
    }

    # create vars file with username/password
    $username = $Credential.UserName
    $password = $Credential.GetNetworkCredential().Password
    $credentialVars = "{ `"ansible_user`": `"$username`", `"ansible_password`": `"$password`" }"
    $credentialFile = New-TemporaryFile
    $credentialVars | Set-Content -Path $credentialFile.FullName

    # select correct inventory
    if ($Protocol -eq 'WinRM') {
        $inventoryFile = 'windows/inventory-winrm.yml'
    } elseif ($Protocol -eq 'SSH') {
        $inventoryFile = 'windows/inventory-ssh.yml'
    }

    # setup other ansible args
    [string[]] $ansibleExtraArgs = $ExtraArgs
    if ($Tags -and ($Tags.Count -gt 0)) {
        $ansibleExtraArgs += "--tags", "$($Tags -join ',')"
    }
    if ($Check) {
        $ansibleExtraArgs += "--check"
    }
    if ($Diff) {
        $ansibleExtraArgs += "--diff"
    }
    if ($WSLPlaybookTags) {
        $ansibleExtraArgs += "-e", "'wsl_playbook_tags=`"$($WSLPlaybookTags -join ',')`"'"
    }

    # convert credential file path to wsl version
    Repair-WslEncoding
    $wslCredentialVarPath = wsl $wslExtraArgs -- wslpath -u "'$($credentialFile.FullName)'"

    # run the playbook
    wsl $wslExtraArgs -- ansible-pull windows/playbook.yml `
      -i $inventoryFile `
      --limit windows `
      -e "@$wslCredentialVarPath" `
      --url https://github.com/tkburns/ansible.git `
      $ansibleExtraArgs
}


##########
#
# Connection
#

function Get-AnsibleConnectionInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$WSLDistro
    )

    [string[]] $wslExtraArgs = @()
    if ($WSLDistro) {
        $wslExtraArgs += "-d", "$WSLDistro"
    }

    $windowsIp = (Get-NetIPConfiguration "vEthernet (WSL)").IPv4Address.IPAddress
    $wslIp = wsl $wslExtraArgs -- hostname -I

    [PSCustomObject] @{ windowsIp=$windowsIp; wslIp=$wslIp }
}


function Disable-AnsibleConnection {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All',

        [Parameter(Mandatory=$false)]
        [switch]$DisableFirewall = $true
    )

    if ($DisableFirewall) {
        # disable firewall
        Set-NetFirewallRule -Group 'Ansible' -Enabled False
    }

    if ($Protocol -in 'WinRM', 'All') {
        # disable powershell remoting
        Disable-PSRemoting

        # disable the winrm service
        Stop-Service winrm
        Set-Service -Name winrm -StartupType Manual
    }

    if ($Protocol -in 'SSH', 'All') {
        # disable SSH service
        Stop-Service sshd
        Set-Service -Name sshd -StartupType 'Disabled'
    }
}


function Enable-AnsibleConnection {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All',

        [Parameter(Mandatory=$false)]
        [switch]$EnableFirewall = $true
    )

    if ($EnableFirewall) {
        # enable firewall
        Set-NetFirewallRule -Group 'Ansible' -Enabled True
    }

    if ($Protocol -in 'WinRM', 'All') {
        # enable powershell remoting/winrm
        Enable-PSRemoting

        # enable the winrm service
        Start-Service winrm
        Set-Service -Name winrm -StartupType Automatic
    }

    if ($Protocol -in 'SSH', 'All') {
        # enable SSH service
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
    }
}


##########
#
# Firewall
#

function Get-AnsibleFirewallRule {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All'
    )

    $rules = Get-NetFirewallRule -Group "Ansible"

    if ($Protocol -eq 'WinRM') {
        $rules = $rules | Where-Object { $_.DisplayName -like "*WinRM*" }
    } elseif ($Protocol -eq 'SSH') {
        $rules = $rules | Where-Object { $_.DisplayName -like "*SSH*" }
    }

    $rules
}

function Add-AnsibleFirewallRule {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All'
    )

    if (($Protocol -eq 'WinRM') -or ($Protocol -eq 'All')) {
        New-NetFirewallRule -DisplayName "Ansible - WinRM HTTPS (WSL)" -Group Ansible -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -Profile Any -InterfaceAlias "vEthernet (WSL)"

    }

    if (($Protocol -eq 'SSH') -or ($Protocol -eq 'All')) {
        New-NetFirewallRule -DisplayName "Ansible - SSH (WSL)" -Group Ansible -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -Profile Any -Program "C:\Program Files\OpenSSH\sshd.exe" -InterfaceAlias "vEthernet (WSL)"
    }
}


function Remove-AnsibleFirewallRule {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All'
    )

    $rules = Get-AnsibleFirewallRule -Protocol $Protocol
    $rules | Remove-NetFirewallRule
}


function Repair-AnsibleFirewallRule {
    [CmdletBinding()]
    Param(
        [ValidateSet('WinRM', 'SSH', 'All')]
        [string]$Protocol = 'All'
    )

    $rules = Get-AnsibleFirewallRule -Protocol $Protocol
    $rules | Set-NetFirewallRule -InterfaceAlias 'vEthernet (WSL)'
}


##########
#
# Utils
#


function Repair-WslEncoding {
    $env:WSL_UTF8 = 1
}

