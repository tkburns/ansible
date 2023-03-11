#!powershell

#AnsibleRequires -CSharpUtil Ansible.Basic

$ErrorActionPreference = 'Stop'

#
# setup module
#

$packageOptions = @{
    id = @{ type = "str" }
    name = @{ type = "str" }
    version = @{ type = "str" }
    source = @{ type = "str" }
    scope = @{ type = "str"; choices = "user", "machine" }
    override = @{ type = "str" }
    state = @{ type = "str"; default = "present"; choices = "absent", "present" }
}

$spec = @{
    options = $packageOptions + @{
        packages = @{
            type = "list"
            elements = "dict"
            options = $packageOptions
            mutually_exclusive = @(, @("id", "name"))
            required_one_of = @(, @("id", "name"))
        }
    }
    mutually_exclusive = @(, @("id", "name", "packages"))
    required_one_of = @(, @("id", "name", "packages"))
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

#
# actions
#

function Run-WingetAction {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Ansible.Basic.AnsibleModule] $Module,

        [hashtable] $Package,
        [string] $DefaultVersion,
        [string] $DefaultSource,
        [ValidateSet("user", "machine")]
        [string] $DefaultScope
    )

    $module.Result.debug += ,@("addressing package:", [string] $package)

    $packageArgs = @{}
    if ($Package.id) {
        $packageArgs.Id = $Package.id
    } elseif ($Package.name) {
        $packageArgs.Name = $Package.name
    } else {
        $Module.FailJson("cannot provide both 'id' and 'name' for a package (id: $Id, name: $Name)")
    }

    if ($Package.scope) {
        $packageArgs.source = $Package.scope
    } elseif ($DefaultScope) {
        $packageArgs.source = $DefaultScope
    }

    if ($Package.source) {
        $packageArgs.source = $Package.source
    } elseif($DefaultSource) {
        $packageArgs.source = $DefaultSource
    }

    if ($Package.override) {
        $packageArgs.override = $Package.override
    }

    if ($package.state -eq "absent") {
        Uninstall-WingetPackage -Module $Module @packageArgs
    } else {
        if ($Package.version) {
            $packageArgs.Version = $Package.version
        } elseif ($DefaultVersion) {
            $packageArgs.Version = $DefaultVersion
        }

        Install-WingetPackage -Module $Module @packageArgs
    }
}

function Install-WingetPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Ansible.Basic.AnsibleModule] $Module,

        [string] $Id,
        [string] $Name,
        [string] $Version,
        [string] $Source,
        [ValidateSet("user", "machine")]
        [string] $Scope,
        [string] $Override
    )

    # TODO - support 'latest' version
    $requestedPackage = [WingetPackage] @{ id = $Id; name = $Name; version = $Version; source = $Source }

    $module.Result.debug += ,@("installing:", [string] $requestedPackage)

    [string[]] $wingetArgs = @()

    if ($Id) {
        $wingetArgs += "--id", $Id
    }

    if ($Name) {
        $wingetArgs += "--name", $Name
    }

    if ($Version) {
        $wingetArgs += "--version", $Version
    }

    if ($Source) {
        $wingetArgs += "--source", $Source
    }

    if ($Scope) {
        $wingetArgs += "--scope", $Scope
    }

    if ($Override) {
        $wingetArgs += "--override", $override
    }

    $preinstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Diff.before += $preinstallPackage
    $module.Result.debug += ,@("preinstallPackage:", [string] $preinstallPackage)

    $existingPackageMatch = Compare-WingetPackage $requestedPackage $preinstallPackage
    $module.Result.debug += ,@("comparison:", $existingPackageMatch)

    if ($existingPackageMatch.IsEqual) {
        $module.Result.changed = $false
        $module.Result.installed += $preinstallPackage
        $module.Diff.after += $preinstallPackage

        return
    } elseif ($module.CheckMode) {
        $module.Result.changed = $true
        $module.Result.installed += $requestedPackage
        $module.Diff.after += $requestedPackage

        return
    }

    $module.Result.debug += ,@("winget command:", "winget install", $wingetArgs)
    winget install $wingetArgs > $null
    
    $postinstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Result.debug += ,@("postinstallPackage:", [string] $postinstallPackage)

    if (-not $postinstallPackage) {
        $packageName = Get-WingetPackageDisplayName -Id $Id -Name $Name -Source $Source -Version $Version
        $module.FailJson("could not find package $packageName after installation")
    }

    $module.Result.changed = -not (Compare-WingetPackage $postinstallPackage $preinstallPackage).IsEqual
    $module.Result.installed += $postinstallPackage
    $module.Diff.after += $postinstallPackage

    $module.Result.debug += ,@("comparison:", (Compare-WingetPackage $postinstallPackage $preinstallPackage))
}

function Uninstall-WingetPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Ansible.Basic.AnsibleModule] $Module,

        [string] $Id,
        [string] $Name,
        [string] $Source,
        [ValidateSet("user", "machine")]
        [string] $Scope
    )

    $module.Result.debug += ,@("uninstalling:", [string] [WingetPackage] @{ id = $Id; name = $Name; source = $Source })

    [string[]] $wingetArgs = @()

    if ($Id) {
        $wingetArgs += "--id", $Id
    }

    if ($Name) {
        $wingetArgs += "--name", $Name
    }

    if ($Source) {
        $wingetArgs += "--source", $Source
    }

    if ($Scope) {
        $wingetArgs += "--scope", $Scope
    }

    $preuninstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Diff.before += $preuninstallPackage
    $module.Result.debug += ,@("preuninstallPackage:", [string] $preuninstallPackage)
    
    if (-not $preuninstallPackage) {
        $module.Result.changed = $false
        $module.Diff.after += $null

        return
    }

    if ($module.CheckMode) {
        $module.Result.changed = $true
        $module.Result.uninstalled += $preuninstallPackage
        $module.Diff.after += $null

        return
    }

    $module.Result.debug += ,@("winget command:", "winget uninstall", $wingetArgs)
    winget uninstall $wingetArgs > $null

    $postuninstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1

    $module.Result.changed = -not (Compare-WingetPackage $preuinstallPackage $postuninstallPackage).IsEqual
    $module.Result.uninstalled += $preuninstallPackage
    $module.Diff.after += $postuninstallPackage

    $module.Result.debug += ,@("postuninstallPackage:", [string] $postuninstallPackage)
    $module.Result.debug += ,@("comparison:", (Compare-WingetPackage $preuinstallPackage $postuninstallPackage))
}

function Get-WingetPackage {
    [CmdletBinding()]
    Param(
        [string] $Id,
        [string] $Name,
        [string] $Source
    )

    [string[]] $wingetArgs = @()

    if ($Id) {
        $wingetArgs += "--id", $Id
    }

    if ($Name) {
        $wingetArgs += "--name", $Name
    }

    if ($Source) {
        $wingetArgs += "--source", $Source
    }

    $packages = winget list $wingetArgs | Format-WingetPackageOutput `
        | Select-Object Id, Name, Source, Version
    [WingetPackage[]] $packages
}

function Find-WingetPackage {
    [CmdletBinding()]
    Param(
        [string] $Id,
        [string] $Name,
        [string] $Source
    )

    [string[]] $wingetArgs = @()

    if ($Id) {
        $wingetArgs += "--id", $Id
    }

    if ($Name) {
        $wingetArgs += "--name", $Name
    }

    if ($Source) {
        $wingetArgs += "--source", $Source
    }
    
    $packages = winget search $wingetArgs | Format-WingetPackageOutput `
        | Select-Object Id, Name, Source, Version
    [WingetPackage[]] $packages
}

function Compare-WingetPackage {
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [WingetPackage] $A,
        [Parameter(Mandatory = $true, Position = 1)]
        [AllowNull()]
        [WingetPackage] $B
    )

    $ret = [PSCustomObject] @{
        Matches = $false
        IsEqual = $false
        IsNull = $false
    }

    if (($A -eq $null) -and ($B -eq $null)) {
        $ret.Matches = $true
        $ret.IsEqual = $true
        $ret.IsNull = $true
    } elseif (($A -ne $null) -and ($B -ne $null)) {
        $idEq = ($A.Id -eq $B.Id) -or (-not $A.Id) -or (-not $B.Id)
        $nameEq = ($A.Name -eq $B.Name) -or (-not $A.Name) -or (-not $B.Name)
        $sourceEq = ($A.Source -eq $B.Source) -or (-not $A.Source) -or (-not $B.Source)
        $versionEq = ($A.Version -eq $B.Version) -or (-not $A.Version) -or (-not $B.Version)

        if ($idEq -and $nameEq -and $sourceEq) {
            $ret.IsEqual = $true
            $ret.Matches = $versionEq
        }
    }

    $ret
}

class WingetPackage {
    [string] $Id
    [string] $Name
    [string] $Source
    [string] $Version

    WingetPackage() {}

    [string] ToString() {
        return $this | Get-WingetPackageDisplayName 
    }
}

function Get-WingetPackageDisplayName {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string] $Id,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string] $Source,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string] $Version
    )

    $packageName = ""
    
    if ($Id) { $packageName += " $Id" }
    if ($Name) { $packageName += " $Name" }
    if ($Version) { $packageName += " $Version" }
    if ($Source) { $packageName += " [$Source]" }
    
    $packageName.Trim()
}

function Format-WingetPackageOutput {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string[]] $Raw
    )

    begin {
       $hyphenLineSeen = $false 
       $fieldInfos = $null
    }

    process {
        foreach ($line in $Raw) {
            $isHyphenLine = $line | Select-String '^-+$'
            $hyphenLineSeen = $hyphenLineSeen -or $isHyphenLine

            if (-not $hyphenLineSeen) {
                # haven't seen hyphen line yet - compute the header
                $header = $line | Select-String '\w'

                if (-not $header) {
                    continue
                }

                $fields = $header.ToString() -split '\s+'
                $fieldStarts = $fields | ForEach-Object { $header.ToString().IndexOf($_) }
                $fieldEndings = $fieldStarts[1..$fieldStarts.Count] + $null

                $fieldInfos = foreach($index in 0..($fields.Count - 1)) {
                    [PSCustomObject]@{
                        field = $fields[$index]
                        start = $fieldStarts[$index]
                        ending = $fieldEndings[$index]
                    }
                }
            } else {
                if (-not ($line | Select-String '\w')) {
                    # skip empty lines
                    continue
                }

                if ($fieldInfos -eq $null) {
                    Write-Error "Unable to parse fields before reaching hyphen line"
                    return
                }

                $obj = @{}

                foreach($fieldInfo in $fieldInfos) {
                    if ($fieldInfo.ending -eq $null) {
                        $obj[$fieldInfo.field] = $line.Substring($fieldInfo.start).Trim()
                    } else {
                        $obj[$fieldInfo.field] = $line.Substring($fieldInfo.start, $fieldInfo.ending - $fieldInfo.start).Trim()
                    }
                }

                [PSCustomObject]$obj
            }
        }
    }
}

#
# run actions & prepare result
#

$module.Result.changed = $false

$module.Result.installed = @()
$module.Result.uninstalled = @()

$module.Diff.before = @()
$module.Diff.after = @()

$module.Result.debug = @()

# TODO - cast packages/params to class (WingetPackageAction?)
if ($module.Params.packages) {
    $defaults = @{
        $DefaultVersion = $module.Params.version
        $DefaultScope = $module.Params.scope
        $DefaultSource = $module.Params.source
    }

    foreach ($package in $module.Params.packages) {
        Run-WingetAction -Module $module -Package $package @defaults
    }
} else {
    Run-WingetAction -Module $module -Package $module.Params
}

# filter $nulls out of installed/uninstalled lists
$module.Result.installed = $module.Result.installed | Where-Object { $null -ne $_ }
$module.Result.uninstalled = $module.Result.uninstalled | Where-Object { $null -ne $_ }

$module.ExitJson()

