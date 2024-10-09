<#
                      7#G~
                    7BB7J#P~
                 .?BG!   .?#G!
                :B@J       .?BB7
             ::  :Y#P~        7BB?.
           ^Y#?    :J#G~        !GB?.
          !&@!       .?#G!        J@B:
       ~^  ^Y#5^       .7BB7    .PB?.  ~^
    .!GB7    :Y#5^        !GB7.  ^.    Y#5^
    7&&~       !@@G~       .P@#J.       J@B^
     :J#G~   ~P#J^?#G!   .?#G~~P#Y:  .7BB7
       .?BG7P#J.   .7BB7J#P~    ^5#Y?BG!
         .?BJ.        7#G~        ^5B!

    Author: Scott McKendry
    Description: PowersShell Profile containing aliases and functions to be loaded when a new PowerShell session is started.
	Added items from Sean Wheeler's universal Profile
	see https://github.com/sdwheeler/seanonit/blob/main/content/downloads/psprofiles/Microsoft.PowerShell_profile.ps1
#>

#region Important global settings
[System.Net.ServicePointManager]::SecurityProtocol =
[System.Net.ServicePointManager]::SecurityProtocol -bor
[System.Net.SecurityProtocolType]::Tls12 -bor
[System.Net.SecurityProtocolType]::Tls13

#endregion

# Imports
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Import Terminal-Icons module - This makes ls (Get-ChildItem) display icons for files and folders
Import-Module Terminal-Icons


# Aliases & Custom Envioronment Variables
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Set-Alias -Name su -Value Start-AdminSession
Set-Alias -Name up -Value Update-Profile
Set-Alias -Name ff -Value Find-File
Set-Alias -Name grep -Value Find-String
Set-Alias -Name touch -Value New-File
Set-Alias -Name df -Value Get-Volume
Set-Alias -Name sed -Value Set-String
Set-Alias -Name which -Value Show-Command
Set-Alias -Name ll -Value Get-ChildItem
Set-Alias -Name la -Value Get-ChildItem
Set-Alias -Name l -Value Get-ChildItem
Set-Alias -Name np -Value "C:\Program Files\Notepad++\notepad++.exe"
Set-Alias -Name vcs -Value "C:\Program Files\Microsoft VS Code\Code.exe"

#region functions
# Putting the FUN in Functions 😎
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
function Find-WindotsRepository {
    <#
    .SYNOPSIS
        Finds the local Windots repository.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ProfilePath
    )

    Write-Verbose "Resolving the symbolic link for the profile"
    $profileSymbolicLink = Get-ChildItem $ProfilePath | Where-Object FullName -EQ $PROFILE.CurrentUserAllHosts
    return Split-Path $profileSymbolicLink.Target
}
function Get-LatestProfile {
    <#
    .SYNOPSIS
        Checks the Github repository for the latest commit date and compares to the local version.
        If the profile is out of date, instructions are displayed on how to update it.
    #>

    Write-Verbose "Checking for updates to the profile"
    $currentWorkingDirectory = $PWD
    Set-Location $ENV:WindotsLocalRepo
    $gitStatus = git status

    if ($gitStatus -like "*Your branch is up to date with*") {
        Write-Verbose "Profile is up to date"
        Set-Location $currentWorkingDirectory
        return
    } else {
        Write-Verbose "Profile is out of date"
        Write-Host "Your PowerShell profile is out of date with the latest commit. To update it, run Update-Profile." -ForegroundColor Yellow
        Set-Location $currentWorkingDirectory
    }
}
function Start-AdminSession {
    <#
    .SYNOPSIS
        Starts a new PowerShell session with elevated rights. Alias: su
    #>
    Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command &{Set-Location $PWD}"
}

function Update-Profile {
    <#
    .SYNOPSIS
        Downloads the latest version of the PowerShell profile from Github and updates the PowerShell profile with the latest version. Alternative to completely restarting the action session.
        Note that functions won't be updated, this requires a full restart. Alias: up
    #>
    Write-Verbose "Storing current working directory in memory"
    $currentWorkingDirectory = $PWD
    Write-Verbose "Updating local profile from Github repository"
    Set-Location $ENV:WindotsLocalRepo
    git pull | Out-Null
    Write-Verbose "Reverting to previous working directory"
    Set-Location $currentWorkingDirectory
    Write-Verbose "Re-running profile script from $($PROFILE.CurrentUserAllHosts)"
    .$PROFILE.CurrentUserAllHosts
}

function Find-File {
    <#
    .SYNOPSIS
        Finds a file in the current directory and all subdirectories. Alias: ff
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory = $true, Position = 0)]
        [string]$SearchTerm
    )

    Write-Verbose "Searching for '$SearchTerm' in current directory and subdirectories"
    $result = Get-ChildItem -Recurse -Filter "*$SearchTerm*" -ErrorAction SilentlyContinue

    Write-Verbose "Outputting results to table"
    $result | Format-Table -AutoSize
}

function Find-String {
    <#
    .SYNOPSIS
        Searches for a string in a file or directory. Alias: grep
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SearchTerm,
        [Parameter(ValueFromPipeline, Mandatory = $false, Position = 1)]
        [string]$Directory,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    Write-Verbose "Searching for '$SearchTerm' in '$Directory'"
    if ($Directory) {
        if ($Recurse) {
            Write-Verbose "Searching for '$SearchTerm' in '$Directory' and subdirectories"
            Get-ChildItem -Recurse $Directory | Select-String $SearchTerm
            return
        }

        Write-Verbose "Searching for '$SearchTerm' in '$Directory'"
        Get-ChildItem $Directory | Select-String $SearchTerm
        return
    }

    if ($Recurse) {
        Write-Verbose "Searching for '$SearchTerm' in current directory and subdirectories"
        Get-ChildItem -Recurse | Select-String $SearchTerm
        return
    }

    Write-Verbose "Searching for '$SearchTerm' in current directory"
    Get-ChildItem | Select-String $SearchTerm
}

function New-File {
    <#
    .SYNOPSIS
        Creates a new file with the specified name and extension. Alias: touch
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )

    Write-Verbose "Creating new file '$Name'"
    New-Item -ItemType File -Name $Name -Path $PWD | Out-Null
}

function Set-String {
    <#
    .SYNOPSIS
        Replaces a string in a file. Alias: sed
    .EXAMPLE
        Set-String -File "C:\Users\Scott\Documents\test.txt" -Find "Hello" -Replace "Goodbye"
    .EXAMPLE
        sed test.txt Hello Goodbye
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$File,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Find,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$Replace
    )
    Write-Verbose "Replacing '$Find' with '$Replace' in '$File'"
    (Get-Content $File).replace("$Find", $Replace) | Set-Content $File
}
function Show-Command {
    <#
    .SYNOPSIS
        Displays the definition of a command. Alias: which
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )
    Write-Verbose "Showing definition of '$Name'"
    Get-Command $Name | Select-Object -ExpandProperty Definition
}
function Get-OrCreateSecret {
    <#
    .SYNOPSIS
        Gets secret from local vault or creates it if it doesn't exist. Requires SecretManagement and SecretStore modules and a local vault to be created.
        Install Modules with:
            Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore
        Create local vault with:
            Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore
            Set-SecretStoreConfiguration -Authentication None -Confirm:$False

        https://devblogs.microsoft.com/powershell/secretmanagement-and-secretstore-are-generally-available/

    .PARAMETER secretName
        Name of the secret to get or create. It's recommended to use the username or public key / client id as secret name to make it easier to identify the secret later.

    .EXAMPLE
        $password = Get-OrCreateSecret -secretName $username

    .EXAMPLE
        $clientSecret = Get-OrCreateSecret -secretName $clientId

    .OUTPUTS
        System.String
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$secretName
    )

    Write-Verbose "Getting secret $secretName"
    $secretValue = Get-Secret $secretName -AsPlainText -ErrorAction SilentlyContinue

    if (!$secretValue) {
        $createSecret = Read-Host "No secret found matching $secretName, create one? Y/N"

        if ($createSecret.ToUpper() -eq "Y") {
            $secretValue = Read-Host -Prompt "Enter secret value for ($secretName)" -AsSecureString
            Set-Secret -Name $secretName -SecureStringSecret $secretValue
            $secretValue = Get-Secret $secretName -AsPlainText
        } else {
            throw "Secret not found and not created, exiting"
        }
    }
    return $secretValue
}

function Update-Modules {
    param (
        [switch]$AllowPrerelease,
        [string]$Name = '*',
        [switch]$WhatIf
    )

    # Test admin privileges without using -Requires RunAsAdministrator,
    # which causes a nasty error message, if trying to load the function within a PS profile but without admin privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Warning ("Function {0} needs admin privileges. Break now." -f $MyInvocation.MyCommand)
        return
    }

    # Get all installed modules
    Write-Host ("Retrieving all installed modules ...") -ForegroundColor Green
    $CurrentModules = Get-InstalledModule -Name $Name -ErrorAction SilentlyContinue | Select-Object Name, Version | Sort-Object Name

    if (-not $CurrentModules) {
        Write-Host ("No modules found.") -ForegroundColor Gray
        return
    } else {
        $ModulesCount = $CurrentModules.Name.Count
        $DigitsLength = $ModulesCount.ToString().Length
        Write-Host ("{0} modules found." -f $ModulesCount) -ForegroundColor Gray
    }

    # Show status of AllowPrerelease Switch
    ''
    if ($AllowPrerelease) {
        Write-Host ("Updating installed modules to the latest PreRelease version ...") -ForegroundColor Green
    } else {
        Write-Host ("Updating installed modules to the latest Production version ...") -ForegroundColor Green
    }

    # Loop through the installed modules and update them if a newer version is available
    $i = 0
    foreach ($Module in $CurrentModules) {
        $i++
        $Counter = ("[{0,$DigitsLength}/{1,$DigitsLength}]" -f $i, $ModulesCount)
        $CounterLength = $Counter.Length
        Write-Host ('{0} Checking for updated version of module {1} ...' -f $Counter, $Module.Name) -ForegroundColor Green
        try {
            $latest = Find-Module $Module.Name -ErrorAction Stop
            if ([version]$Module.Version -lt [version]$latest.version) {
                Update-Module -Name $Module.Name -AllowPrerelease:$AllowPrerelease -AcceptLicense -Scope:AllUsers -Force:$True -ErrorAction Stop -WhatIf:$WhatIf.IsPresent
            }
        } catch {
            Write-Host ("{0$CounterLength} Error updating module {1}!" -f ' ', $Module.Name) -ForegroundColor Red
        }

        # Retrieve newest version number and remove old(er) version(s) if any
        $AllVersions = Get-InstalledModule -Name $Module.Name -AllVersions | Sort-Object PublishedDate -Descending
        $MostRecentVersion = $AllVersions[0].Version
        if ($AllVersions.Count -gt 1 ) {
            Foreach ($Version in $AllVersions) {
                if ($Version.Version -ne $MostRecentVersion) {
                    try {
                        Write-Host ("{0,$CounterLength} Uninstalling previous version {1} of module {2} ..." -f ' ', $Version.Version, $Module.Name) -ForegroundColor Gray
                        Uninstall-Module -Name $Module.Name -RequiredVersion $Version.Version -Force:$True -ErrorAction Stop -AllowPrerelease -WhatIf:$WhatIf.IsPresent
                    } catch {
                        Write-Warning ("{0,$CounterLength} Error uninstalling previous version {1} of module {2}!" -f ' ', $Version.Version, $Module.Name)
                    }
                }
            }
        }
    }

    # Get the new module versions for comparing them to to previous one if updated
    $NewModules = Get-InstalledModule -Name $Name | Select-Object Name, Version | Sort-Object Name
    if ($NewModules) {
        ''
        Write-Host ("List of updated modules:") -ForegroundColor Green
        $NoUpdatesFound = $true
        foreach ($Module in $NewModules) {
            $CurrentVersion = $CurrentModules | Where-Object Name -EQ $Module.Name
            if ($CurrentVersion.Version -notlike $Module.Version) {
                $NoUpdatesFound = $false
                Write-Host ("- Updated module {0} from version {1} to {2}" -f $Module.Name, $CurrentVersion.Version, $Module.Version) -ForegroundColor Green
            }
        }

        if ($NoUpdatesFound) {
            Write-Host ("No modules were updated.") -ForegroundColor Gray
        }
    }
}
#endregion

if ($PSVersionTable.PSVersion -lt '6.0') {
    Write-Verbose 'Setting up PowerShell 5.x environment...'
    # The $Is* variables are not defined in PowerShell 5.1
    $IsLinux = $IsMacOS = $IsCoreCLR = $false
    $IsWindows = $true

    # Fix the case of the PSReadLine module so that Update-Help works
    Write-Verbose 'Reloading PSReadLine...'
    Remove-Module PSReadLine
    Import-Module PSReadLine

    Set-PSReadLineOption -PredictionSource 'History'
}

if ($PSVersionTable.PSVersion -ge '7.2') {
    Write-Verbose 'Setting up PowerShell 7.2+ environment...'
    # PSReadLine Options
    import-module PSReadLine
    Sleep 3
    Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineOption -PredictionSource History
    Set-PSReadLineOption -PredictionSource 'HistoryAndPlugin'
    Import-Module CompletionPredictor # Requires PSSubsystemPluginModel experimental feature
}


#-------------------------------------------------------
#region OS-specific initialization (all versions)
#-------------------------------------------------------
if ($IsWindows) {
    # Create custom PSDrives
    if (!(Test-Path HKCR:)) {
        $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    }

    # Check for admin privileges
    & {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal] $identity
        $global:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    }

    # Register the winget argument completer
    Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
        $Local:word = $wordToComplete.Replace('"', '""')
        $Local:ast = $commandAst.ToString().Replace('"', '""')
        winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
} elseif ($IsLinux) {
    Import-Module -Name Microsoft.PowerShell.UnixTabCompletion
    Import-PSUnixTabCompletion
} elseif ($IsMacOS) {
    Import-Module -Name Microsoft.PowerShell.UnixTabCompletion
    Import-PSUnixTabCompletion
}
#endregion

#-------------------------------------------------------
#region PSReadLine settings
#-------------------------------------------------------
Write-Verbose 'Setting up PSReadLine...'
## Add Dongbo's custom history handler to filter out:
## - Commands with 3 or fewer characters
## - Commands that start with a space
## - Commands that end with a semicolon
## - Start with a space or end with a semicolon if you want the command to be omitted from history
##   - Useful for filtering out sensitive commands you don't want recorded in history
$global:__defaultHistoryHandler = (Get-PSReadLineOption).AddToHistoryHandler
Set-PSReadLineOption -AddToHistoryHandler {
    param([string]$line)

    $defaultResult = $global:__defaultHistoryHandler.Invoke($line)
    if ($defaultResult -eq "MemoryAndFile") {
        if ($line.Length -gt 3 -and $line[0] -ne ' ' -and $line[-1] -ne ';') {
            return "MemoryAndFile"
        } else {
            return "MemoryOnly"
        }
    }
    return $defaultResult
}
#-------------------------------------------------------
#endregion

$PSROptions = @{
    Colors = @{
        Operator         = $PSStyle.Foreground.BrightMagenta
        Parameter        = $PSStyle.Foreground.BrightMagenta
        Selection        = $PSStyle.Foreground.BrightGreen + $PSStyle.Background.BrightBlack
        InLinePrediction = $PSStyle.Background.BrightBlack
    }
}
Set-PSReadLineOption @PSROptions

# Custom Environment Variables
$ENV:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ENV:WindotsLocalRepo = Find-WindotsRepository -ProfilePath $PSScriptRoot

# Prompt Setup
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#Oh-My-Posh init pwsh --config "$env:POSH_THEMES_PATH/poshmon.omp.json" | Invoke-Expression
#Oh-My-Posh init pwsh --config "$env:POSH_THEMES_PATH/gruvbox.omp.json" | Invoke-Expression
#Oh-My-Posh init pwsh --config "$env:POSH_THEMES_PATH/rudolfs-dark.omp.json" | Invoke-Expression
Oh-My-Posh init pwsh --config "$env:POSH_THEMES_PATH/agnoster.minimal.omp.json" | Invoke-Expression
#Oh-My-Posh init pwsh --config "$env:POSH_THEMES_PATH/powerline.omp.json" | Invoke-Expression
# Check for updates
Get-LatestProfile

C:\Users\alain\OneDrive\Codevault\PoSH\show-gittip.ps1