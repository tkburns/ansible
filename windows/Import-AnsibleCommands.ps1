# Requirements:
# - PowerShell >= 3.0
# - .NET >= 4.0
# - PS Scripts enabled (ExecutionPolicy)
#
# Any modern windows desktop should meet the PowerShell & .NET
# requirements out of the box
#
# Enable scripts via the following:
# > Set-ExecutionPolicy RemoteSigned -Scope Process
# (or use -Scope CurrentUser to make it persistent)

# TODO List
# - add 'WhatIf' param

function Install-Ansible {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]SetupWinRM = $true

        [Parameter(Mandatory=$false)]
        [switch]SetupSSH

        [Parameter(Mandatory=$false)]
        [string]WSLDistro
    )

    ##########
    #
    # Prep
    #

    # install wsl
    if ($WSLDistro) {
        wsl --install -d ${WSLDistro}
    } else {
        wsl --install
    }

    if ($SeuptWinRM) {

        ##########
        #
        # Setup WinRM (PSRemoting)
        #

        Enable-PSRemoting

        # setup HTTPS listener
        $cert = New-SelfSignedCertificate -FriendlyName '(Ansible) WinRM' -DnsName 'ansible.windows' -Type SSLServerAuthentication
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = "HTTPS"; Address = "*" } -ValueSet @{ Hostname = 'ansible.windows'; CertificateThumbprint = $cert.Thumbprint }

        # setup firewall
        Disable-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'
        New-NetFirewallRule -DisplayName "Ansible - WinRM HTTPS (WSL)" -Group Ansible -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -Profile Any -InterfaceAlias "vEthernet (WSL)"

    }

    if ($SetupSSH) {

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
        # -Name "OpenSSH-Server-In-TCP"
        New-NetFirewallRule -DisplayName "Ansible - SSH (WSL)" -Group Ansible -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -Profile Any -Program "C:\Program Files\OpenSSH\sshd.exe" -InterfaceAlias "vEthernet (WSL)"
    
    }


    ###########
    #
    # Install Ansible on WSL (Ubuntu) for controlling windows
    #

    # install ansible
    wsl -- `
      sudo apt install -y software-properties-common '&&' `
      sudo apt-add-repository --yes --update ppa:ansible/ansible '&&' `
      sudo apt install -y python3 python3-pip ansible

    # install ansible command completion
    wsl -- `
      pip3 install argcomplete '&&' `
      activate-global-python-argcomplete --user

    # install winrm
    wsl -- pip3 install pywinrm

}

function Uninstall-Ansible {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$CleanFirewall = $true

        [Parameter(Mandatory=$false)]
        [switch]$DisableWinRM = $true

        [Parameter(Mandatory=$false)]
        [switch]$CleanWinRM = $true

        [Parameter(Mandatory=$false)]
        [switch]$UninstallSSH = $true

        [Parameter(Mandatory=$false)]
        [switch]$CleanWSL

        [Parameter(Mandatory=$false)]
        [switch]$RemoveWSL

        [Parameter(Mandatory=$false)]
        [string]$WSLDistro
    )

    if ($CleanFirewall) {
        # delete firewall rules
        Remove-NetFirewallRule -Group 'Ansible'
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
        } elseif ($Distro -eq $null) {
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
        if ($WSLDistro) {
            $distroFlag = "-d $WSLDistro"
        }

        # remove just ansible-specific things
        wsl $distroFlag -- `
          pip3 uninstall pywinrm '&&' `
          sudo apt uninstall ansible '&&' `
          sudo apt-add-repository -r ppa:ansible/ansible
    }
}

function Get-AnsibleConnectionInfo {
    $windowsIp = (Get-NetIPConfiguration "vEthernet (WSL)").IPv4Address.IPAddress
    $wslIp = wsl hostname -I

    # TODO - create a class???
    @{ windowsIp=$windowsIp; wslIp=$wslIp }
}

function Disable-AnsibleConnection {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$DisableFirewall = $true

        [Parameter(Mandatory=$false)]
        [switch]$DisableWinRM = $true

        [Parameter(Mandatory=$false)]
        [switch]$DisableSSH = $true
    )

    if ($DisableFirewall) {
        # disable firewall
        Set-NetFirewallRule -Group 'Ansible' -Enabled False
    }

    if ($DisableWinRM) {
        # disable powershell remoting
        Disable-PSRemoting

        # disable the winrm service
        Stop-Service winrm
        Set-Service -Name winrm -StartupType Manual
    }

    if ($DisableSSH) {
        # disable SSH
        Stop-Service sshd
        Set-Service -Name sshd -StartupType 'Disabled'
    }
}

function Enable-AnsibleConnection {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$EnableFirewall = $true

        [Parameter(Mandatory=$false)]
        [switch]$EnableWinRM = $true

        [Parameter(Mandatory=$false)]
        [switch]$EnableSSH = $true
    )

    if ($EnableFirewall) {
        # enable firewall
        Set-NetFirewallRule -Group 'Ansible' -Enabled True
    }

    if ($EnableWinRM) {
        # enable powershell remoting/winrm
        Enable-PSRemoting

        # disable the winrm service
        Start-Service winrm
        Set-Service -Name winrm -StartupType Automatic
    }

    if ($EnableSSH) {
        # enable SSH
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
    }
}


##########
#
# Utils
#

function Repair-WslEncoding {
    $env:WSL_UTF8 = 1
}

