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
        [string] $DefaultSource
    )

    $module.Result.debug += ,@("addressing package:", $package)

    $id_name = @{}
    if ($Package.id) {
        $id_name.Id = $Package.id
    } elseif ($Package.name) {
        $id_name.Name = $Package.name
    } else {
        $Module.FailJson("cannot provide both 'id' and 'name' for a package (id: $Id, name: $Name)")
    }

    if ($package.state -eq "absent") {
        if ($Package.source) {
            $source = $Package.Source
        } else {
            $source = $DefaultSource
        }

        Uninstall-WingetPackage -Module $Module @id_name -Source $source
    } else {
        if ($Package.version) {
            $version = $Package.Version
        } else {
            $version = $DefaultVersion
        }
 
        if ($Package.source) {
            $source = $Package.Source
        } else {
            $source = $DefaultSource
        }

        Install-WingetPackage -Module $Module @id_name -Version $version -Source $source
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
        [string] $Source
    )

    $module.Result.debug += ,@("installing:", @{ id = $Id; name = $Name; version = $Version; source = $Source })

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

    $preinstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Diff.before += $preinstallPackage
    $module.Result.debug += ,@("preinstallPackage:", $preinstallPackage)

    if ($module.CheckMode) {
        $package = Find-WingetPackage -Id $Id -Name $Name -Source $Source -Version $Version | Select-Object -First 1
        $module.Result.debug += ,@("search package:", $package)

        if (-not $package) {
            $packageName = Get-WingetPackageDisplayName -Id $Id -Name $Name -Source $Source -Version $Version
            $module.FailJson("could not find package $packageName")
        }

        $module.Result.changed = -not (Compare-WingetPackage $package $preinstallPackage).IsEqual
        $module.Result.installed += $package
        $module.Diff.after += $package

        $module.Result.debug += ,@("comparison:", (Compare-WingetPackage $package $preinstallPackage))

        return
    }

    winget install $wingetArgs > $null
    $module.Result.debug += ,@("winget command:", "winget install", $wingetArgs)
    
    $postinstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Diff.after += $postinstallPackage
    $module.Result.debug += ,@("postinstallPackage:", $postinstallPackage)

    if (-not $postinstallPackage) {
        $packageName = Get-WingetPackageDisplayName -Id $Id -Name $Name -Source $Source -Version $Version
        $module.FailJson("could not find package $packageName")
    }

    $module.Result.changed = -not (Compare-WingetPackage $postinstallPackage $preinstallPackage).IsEqual
    $module.Result.installed += $postinstallPackage

    $module.Result.debug += ,@("comparison:", (Compare-WingetPackage $postinstallPackage $preinstallPackage))
}

function Uninstall-WingetPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Ansible.Basic.AnsibleModule] $Module,

        [string] $Id,
        [string] $Name,
        [string] $Source
    )

    $module.Result.debug += ,@("uninstalling:", @{ id = $Id; name = $Name; source = $Source })

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

    $preuninstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1
    $module.Diff.before += $preuninstallPackage
    $module.Result.debug += ,@("preuninstallPackage:", $preuninstallPackage)
    
    if (-not $preuninstallPackage) {
        $module.Result.changed = $false
        $module.Diff.after += $null

        return
    }

    $module.Result.uninstalled += $preuninstallPackage

    if ($module.CheckMode) {
        $module.Result.changed = $true
        $module.Diff.after += $null

        return
    }

    winget uninstall $wingetArgs > $null
    $module.Result.debug += ,@("winget command:", "winget uninstall", $wingetArgs)

    $postuninstallPackage = Get-WingetPackage -Id $Id -Name $Name -Source $Source | Select-Object -First 1

    $module.Result.changed = -not (Compare-WingetPackage $preuinstallPackage $postuninstallPackage).IsEqual
    $module.Diff.after += $postuninstallPackage

    $module.Result.debug += ,@("postuninstallPackage:", $postuninstallPackage)
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

    [WingetPackage[]] (winget list $wingetArgs | Format-WingetPackageOutput)
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
    
    [WingetPackage[]] (winget list $wingetArgs | Format-WingetPackageOutput)
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
        Matches = $true
        IsEqual = $true
        IsNull = $false
    }

    if (($A -eq $null) -and ($B -eq $null)) {
        $ret.IsNull = $true
    } elseif (($A -eq $null) -or ($B -eq $null)) {
        $ret.Matches = $false
        $ret.IsEqual = $false
    } else {
        if (($A.Id -ne $B.Id) -or ($A.Source -ne $B.Source)) {
            $ret.IsEqual = $false
            $ret.Matches = $false
        } elseif ($A.Version -ne $B.Version) {
            $ret.IsEqual = $false
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
    
    if ($Source) { $packageName += " [$Source]" }
    if ($Id) { $packageName += " $Id" }
    if ($Name) { $packageName += " $Name" }
    if ($Version) { $packageName += " $Version" }
    
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

if ($module.Params.packages) {
    $defaults = @{
        $DefaultVersion = $module.Params.version
        $DefaultSource = $module.Params.source
    }

    foreach ($package in $module.Params.packages) {
        Run-WingetAction -Module $module -Package $package -DefaultVersion @defaults
    }
} else {
    Run-WingetAction -Module $module -Package $module.Params
}

# filter $nulls out of installed/uninstalled lists
$module.Result.installed = $module.Result.installed | Where-Object { $null -ne $_ }
$module.Result.uninstalled = $module.Result.uninstalled | Where-Object { $null -ne $_ }

$module.ExitJson()

