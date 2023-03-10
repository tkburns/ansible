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
    # Install Ansible on WSL for controlling windows
    #

    Install-WSLAnsible -WSLDistro $WSLDistro -InstallWinRM:($Protocol -in 'WinRM', 'All')
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
        [string[]] $wslDistroArg = @()
        if ($WSLDistro) {
            $wslDistroArg += "-d", "$WSLDistro"
        }

        # remove just ansible-specific things
        wsl $wslDistroArg -- `
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

        [byte]$VerboseLevel,

        [string[]]$ExtraArgs
    )

    # get credentials if not provided
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Enter your windows username/password" -UserName $env:UserName
    }

    # setup wsl args (distro)
    [string[]] $wslDistroArg = @()
    if ($WSLDistro) {
        $wslDistroArg += "-d", "$WSLDistro"
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

    # setup ansible run args
    [string[]] $ansibleExtraArgs = @()
    if ($Tags -and ($Tags.Count -gt 0)) {
        $ansibleExtraArgs += "--tags", "$($Tags -join ',')"
    }
    if ($Check) {
        $ansibleExtraArgs += "--check"
    }
    if ($Diff) {
        $ansibleExtraArgs += "--diff"
    }
    if ($VerboseLevel) {
        $verboseFlag = "-" + ('v' * $VerboseLevel)
        $ansibleExtraArgs += $verboseFlag
    }
    $ansibleExtraArgs += $ExtraArgs

    # convert credential file path to wsl version
    Repair-WslEncoding
    $wslCredentialVarPath = wsl $wslDistroArg -- wslpath -u "'$($credentialFile.FullName)'"

    # run the playbook
    wsl $wslDistroArg -- ansible-pull windows/playbook.yml `
      -i $inventoryFile `
      --limit windows `
      -e "@$wslCredentialVarPath" `
      --url https://github.com/tkburns/ansible.git `
      $ansibleExtraArgs
}


##########
#
# WSL
#

function Install-WSLAnsible {
    param (
        [Parameter(Mandatory=$false)]
        [string]$WSLDistro,

        [Parameter(Mandatory=$false)]
        [switch]$InstallWinRM
    )

    Repair-WSLEncoding

    [string[]] $wslDistroArg = @()
    if ($WSLDistro) {
        $wslDistroArg += "-d", "$WSLDistro"
    }

    if ($WSLDistro) {
        $installed = wsl --list | Select-String $WSLDistro
    } else {
        $installed = wsl --list
    }

    if (-not $installed) {
        wsl --install $wslDistroArg
    }

    # install ansible
    wsl $wslDistroArg -- `
      sudo apt-add-repository --yes --update ppa:ansible/ansible '&&' `
      sudo apt-get update -y '&&' `
      sudo apt-get install -y curl git software-properties-common python3 python3-pip ansible

    # install ansible command completion?
    wsl $wslDistroArg -- `
      python3 -m pip install --user argcomplete '&&' `
      activate-global-python-argcomplete --user

    # install winrm
    if ($InstallWinRM) {
        wsl $wslDistroArg -- pip3 install pywinrm
    }
}

function Uninstall-WSLAnsible {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RemoveDistro')]
        [string]$WSLDistro,

        [switch]$RemovePython,

        [Parameter(Mandatory = $true, ParameterSetName = 'RemoveDistro')]
        [switch]$RemoveWSLDistro
    )

    [string[]] $wslDistroArg = @()
    if ($WSLDistro) {
        $wslDistroArg += "-d", "$WSLDistro"
    }

    if ($RemoveWSLDistro) {
        if ($WSLDistro) {
            wsl --unregister $WSLDistro
            return
        } else {
            throw [System.ArgumentException] "RemoveWSLDistro requires WSLDistro be set"
        }
    }

    # uninstall winrm
    wsl $wslDistroArg -- pip3 uninstall -y pywinrm

    if ($RemovePython) {
        wsl $wslDistroArg -- `
          sudo apt-get uninstall -y python3-pip python3
    }

    # remove just ansible-specific things
    wsl $wslDistroArg -- `
      sudo apt-add-repository -r ppa:ansible/ansible '&&' `
      sudo apt-get uninstall -y ansible
}

function Invoke-WSLAnsiblePlaybook {
    [CmdletBinding()]
    Param(
        [string]$WSLDistro,

        [switch]$Check,
        [switch]$Diff,

        [string[]]$Tags,

        [byte]$VerboseLevel,

        [string]$SSHKeyFilename,
        [string]$SSHKeyPassphrase,
        [string]$GPGKeyName,
        [string]$GPGKeyEmail,
        [string]$GPGKeyPassphrase,

        [string[]]$ExtraArgs
    )

    # setup wsl args (distro)
    [string[]] $wslDistroArg = @()
    if ($WSLDistro) {
        $wslDistroArg += "-d", "$WSLDistro"
    }

    # setup ansible run args
    [string[]] $ansibleExtraArgs = @()
    if ($Tags -and ($Tags.Count -gt 0)) {
        $ansibleExtraArgs += "--tags", "$($Tags -join ',')"
    }
    if ($Check) {
        $ansibleExtraArgs += "--check"
    }
    if ($Diff) {
        $ansibleExtraArgs += "--diff"
    }
    if ($VerboseLevel) {
        $verboseFlag = "-" + ('v' * $VerboseLevel)
        $ansibleExtraArgs += $verboseFlag
    }
    $ansibleExtraArgs += $ExtraArgs

    # setup ansible vars
    $vars = @()
    if ($SSHKeyFilename) {
        $vars += @{ name = "ssh_key_filename"; value = $SSHKeyFilename }
    }
    if ($SSHKeyPassphrase) {
        $vars += @{ name = "ssh_key_passphrase"; value = $SSHKeyPassphrase }
    }
    if ($GPGKeyName) {
        $vars += @{ name = "gpg_key_name"; value = $GPGKeyName }
    }
    if ($GPGKeyEmail) {
        $vars += @{ name = "gpg_key_email"; value = $GPGKeyEmail }
    }
    if ($GPGKeyPassphrase) {
        $vars += @{ name = "gpg_key_passphrase"; value = $GPGKeyPassphrase }
    }

    $varsFlag = ""
    if ($vars.Count -gt 0) {
        $varPairs = $vars | Foreach-Object {
            $name = $_.name
            $escaped = $_.value -replace '\\','\\' -replace "(['`"])",'\$1'
            "$name=\`"$escaped\`""
        }
        $varsFlag = "-e", "'$($varPairs -join ' ')'"
    }

    # run the playbook
    wsl $wslDistroArg -- ansible-pull linux/wsl-playbook.yml `
      --url https://github.com/tkburns/ansible.git `
      $varsFlag `
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

    [string[]] $wslDistroArg = @()
    if ($WSLDistro) {
        $wslDistroArg += "-d", "$WSLDistro"
    }

    $windowsIp = (Get-NetIPConfiguration "vEthernet (WSL)").IPv4Address.IPAddress
    $wslIp = wsl $wslDistroArg -- hostname -I

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

