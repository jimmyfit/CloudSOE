Set-StrictMode -Version latest
$ErrorActionPreference = 'Stop'

Import-Module $PSScriptRoot/DscOperations.psm1 -Force

function Update-PolicyParameter {
    [CmdletBinding()]
    param
    (
        [parameter()]
        [Hashtable[]]
        $parameter
    )
    $updatedParameterInfo = @()

    foreach ($parmInfo in $Parameter) {
        $param = @{ }
        $param['Type'] = 'string'

        if ($parmInfo.Contains('Name')) {
            $param['ReferenceName'] = $parmInfo.Name
        }
        else {
            Throw "Policy parameter is missing a mandatory property 'Name'. Please make sure that parameter name is specified in Policy parameter."
        }

        if ($parmInfo.Contains('DisplayName')) {
            $param['DisplayName'] = $parmInfo.DisplayName
        }
        else {
            Throw "Policy parameter is missing a mandatory property 'DisplayName'. Please make sure that parameter display name is specified in Policy parameter."
        }
        
        if ($parmInfo.Contains('Description')) {
            $param['Description'] = $parmInfo.Description
        }

        if (-not $parmInfo.Contains('ResourceType')) {
            Throw "Policy parameter is missing a mandatory property 'ResourceType'. Please make sure that configuration resource type is specified in Policy parameter."
        }
        elseif (-not $parmInfo.Contains('ResourceId')) {
            Throw "Policy parameter is missing a mandatory property 'ResourceId'. Please make sure that configuration resource Id is specified in Policy parameter."
        }
        else {
            $param['MofResourceReference'] = "[$($parmInfo.ResourceType)]$($parmInfo.ResourceId)"
        }

        if ($parmInfo.Contains('ResourcePropertyName')) {
            $param['MofParameterName'] = $parmInfo.ResourcePropertyName
        }
        else {
            Throw "Policy parameter is missing a mandatory property 'ResourcePropertyName'. Please make sure that configuration resource property name is specified in Policy parameter."
        }
        
        if ($parmInfo.Contains('DefaultValue')) {
            $param['DefaultValue'] = $parmInfo.DefaultValue
        }

        if ($parmInfo.Contains('AllowedValues')) {
            $param['AllowedValues'] = $parmInfo.AllowedValues
        }

        $updatedParameterInfo += $param;
    }

    return $updatedParameterInfo
}

function Test-GuestConfigurationMofResourceDependencies {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    $externalResources = @()
    for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++) {
        if ($resourcesInMofDocument[$i].CimInstanceProperties.Name -contains 'ModuleName' -and $resourcesInMofDocument[$i].ModuleName -ne 'GuestConfiguration') {
            if ($resourcesInMofDocument[$i].ModuleName -ieq 'PsDesiredStateConfiguration') {
                Throw "'PsDesiredStateConfiguration' module is not supported by GuestConfiguration. Please use 'PSDSCResources' module instead of 'PsDesiredStateConfiguration' module in DSC configuration."
            }

            $configurationName = $resourcesInMofDocument[$i].ConfigurationName
            Write-Warning -Message "The configuration '$configurationName' is using one or more resources outside of the GuestConfiguration module. Please make sure these resources work with PowerShell Core"
            break
        }
    }
}

function Copy-DscResources {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $MofDocumentPath,

        [Parameter(Mandatory = $true)]
        [String]
        $Destination,

        [switch] $Force
    )
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($MofDocumentPath, 4)

    Write-Verbose 'Copy DSC resources ...'
    $modulePath = New-Item -ItemType Directory -Force -Path (Join-Path $Destination 'Modules')
    $guestConfigModulePath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath 'GuestConfiguration')
    try {
        $latestModule = @()
        $latestModule += Get-Module GuestConfiguration
        $latestModule += Get-Module GuestConfiguration -ListAvailable
        $latestModule = ($latestModule | Sort-Object Version -Descending)[0]
    }
    catch {
        write-error 'unable to find the GuestConfiguration module either as an imported module or in $env:PSModulePath'
    }
    Copy-Item "$($latestModule.ModuleBase)/DscResources/" "$guestConfigModulePath/DscResources/" -Recurse -Force
    Copy-Item "$($latestModule.ModuleBase)/helpers/" "$guestConfigModulePath/helpers/" -Recurse -Force
    Copy-Item "$($latestModule.ModuleBase)/GuestConfiguration.psd1" "$guestConfigModulePath/GuestConfiguration.psd1" -Force
    Copy-Item "$($latestModule.ModuleBase)/GuestConfiguration.psm1" "$guestConfigModulePath/GuestConfiguration.psm1" -Force
    
    # Copies DSC resource modules
    $modulesToCopy = @{ }
    $resourcesInMofDocument | ForEach-Object {
        if ($_.CimInstanceProperties.Name -contains 'ModuleName' -and $_.CimInstanceProperties.Name -contains 'ModuleVersion') {
            if ($_.ModuleName -ne 'GuestConfiguration') {
                $modulesToCopy[$_.CimClass.CimClassName] = @{ModuleName = $_.ModuleName; ModuleVersion = $_.ModuleVersion }
            }
        }
    }

    # PowerShell modules required by DSC resource module
    $powershellModulesToCopy = @{ }
    $modulesToCopy.Values | ForEach-Object {
        if ($_.ModuleName -ne 'GuestConfiguration') {
            $requiredModule = Get-Module -FullyQualifiedName @{ModuleName = $_.ModuleName; RequiredVersion = $_.ModuleVersion } -ListAvailable
            if (($requiredModule | Get-Member -MemberType 'Property' | ForEach-Object { $_.Name }) -contains 'RequiredModules') {
                $requiredModule.RequiredModules | ForEach-Object {
                    if ($null -ne $_.Version) {
                        $powershellModulesToCopy[$_.Name] = @{ModuleName = $_.Name; ModuleVersion = $_.Version }
                        Write-Verbose "$($_.Name) is a required PowerShell module"
                    }
                    else {
                        Write-Error "Unable to add required PowerShell module $($_.Name).  No version was specified in the module manifest RequiredModules property.  Please use module specification '@{ModuleName=;ModuleVersion=}'."
                    }
                }
            }
        }
    }

    $modulesToCopy += $powershellModulesToCopy

    $modulesToCopy.Values | ForEach-Object {
        $moduleToCopy = Get-Module -FullyQualifiedName @{ModuleName = $_.ModuleName; RequiredVersion = $_.ModuleVersion } -ListAvailable
        if ($null -ne $moduleToCopy) {
            if ($_.ModuleName -eq 'PSDesiredStateConfiguration') {
                Write-Error 'The configuration includes DSC resources from the Windows PowerShell 5.1 module "PSDesiredStateConfiguration" that are not available in PowerShell Core. Switch to the "PSDSCResources" module available from the PowerShell Gallery. Note that the File and Package resources are not yet available in "PSDSCResources".'
            }
            $moduleToCopyPath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath $_.ModuleName)
            Copy-Item "$($moduleToCopy.ModuleBase)/*" $moduleToCopyPath -Recurse -Force:$Force
        }
        else {
            Write-Error "Module $($_.ModuleName) version $($_.ModuleVersion) could not be found in `$env:PSModulePath"
        }
    }

    # Copy binary resources.
    $nativeResourcePath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath 'DscNativeResources')
    $resources = Get-DscResource -Module @{ModuleName='GuestConfiguration'; ModuleVersion=$latestModule.Version.ToString()}
    $resources | ForEach-Object {
        if ($_.ImplementedAs -eq 'Binary') {
            $binaryResourcePath = Join-Path (Join-Path $latestModule.ModuleBase 'DscResources') $_.ResourceType
            Get-ChildItem $binaryResourcePath/* -Include *.sh -Recurse | ForEach-Object { Convert-FileToUnixLineEndings -FilePath $_ }
            Copy-Item $binaryResourcePath/* -Include *.sh $modulePath -Recurse -Force
            Copy-Item $binaryResourcePath $nativeResourcePath -Recurse -Force
        }
    }

    # Remove DSC binaries from package (just a safeguard).
    $binaryPath = Join-Path $guestConfigModulePath 'bin'
    Remove-Item -Path $binaryPath -Force -Recurse -ErrorAction 'SilentlyContinue' | Out-Null
}

function Copy-ChefInspecDependencies {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PackagePath,

        [Parameter(Mandatory = $true)]
        [String]
        $Configuration,

        [string]
        $ChefInspecProfilePath
    )

    # Copy Inspec install script and profiles.
    $modulePath = Join-Path $PackagePath 'Modules'
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Configuration, 4)
    $missingDependencies = @()
    $chefInspecProfiles = @()
    
    $resourcesInMofDocument | ForEach-Object {
        if ($_.CimClass.CimClassName -eq 'MSFT_ChefInSpecResource') {
            if ([string]::IsNullOrEmpty($ChefInspecProfilePath)) {
                Throw "'$($_.CimInstanceProperties['Name'].Value)'. Please use ChefInspecProfilePath parameter to specify profile path."
            }

            $inspecProfilePath = Join-Path $ChefInspecProfilePath $_.CimInstanceProperties['Name'].Value
            if (-not (Test-Path $inspecProfilePath)) {
                $missingDependencies += $_.CimInstanceProperties['Name'].Value
            }
            else {
                $chefInspecProfiles += $inspecProfilePath
            }

        }
    }

    if ($missingDependencies.Length) {
        Throw "Failed to find Chef Inspec profile for '$($missingDependencies -join ',')'. Please make sure profile is present on $ChefInspecProfilePath path."
    }

    $chefInspecProfiles | ForEach-Object { Copy-Item $_ $modulePath -Recurse -Force -ErrorAction SilentlyContinue }

}

function Convert-FileToUnixLineEndings {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $fileContent = Get-Content -Path $FilePath -Raw
    $fileContentWithLinuxLineEndings = $fileContent.Replace("`r`n", "`n")
    $null = Set-Content -Path $FilePath -Value $fileContentWithLinuxLineEndings -Force -NoNewline
    Write-Verbose -Message "Converted the file at the path '$FilePath' to Unix line endings."
}

function Update-MofDocumentParameters {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [parameter()]
        [Hashtable[]] $Parameter
    )

    if ($Parameter.Count -eq 0) {
        return
    }

    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    foreach ($parmInfo in $Parameter) {
        if (-not $parmInfo.Contains('ResourceType')) {
            Throw "Policy parameter is missing a mandatory property 'ResourceType'. Please make sure that configuration resource type is specified in configuration parameter."
        }
        if (-not $parmInfo.Contains('ResourceId')) {
            Throw "Policy parameter is missing a mandatory property 'ResourceId'. Please make sure that configuration resource Id is specified in configuration parameter."
        }
        if (-not $parmInfo.Contains('ResourcePropertyName')) {
            Throw "Policy parameter is missing a mandatory property 'ResourcePropertyName'. Please make sure that configuration resource property name is specified in configuration parameter."
        }
        if (-not $parmInfo.Contains('ResourcePropertyValue')) {
            Throw "Policy parameter is missing a mandatory property 'ResourcePropertyValue'. Please make sure that configuration resource property value is specified in configuration parameter."
        }

        $resourceId = "[$($parmInfo.ResourceType)]$($parmInfo.ResourceId)"
        if ($null -eq ($resourcesInMofDocument | Where-Object { `
                    ($_.CimInstanceProperties.Name -contains 'ResourceID') `
                        -and ($_.CimInstanceProperties['ResourceID'].Value -eq $resourceId) `
                        -and ($_.CimInstanceProperties.Name -contains $parmInfo.ResourcePropertyName) `
                })) {

            Throw "Failed to find parameter reference in the configuration '$Path'. Please make sure parameter with ResourceType:'$($parmInfo.ResourceType)', ResourceId:'$($parmInfo.ResourceId)' and ResourcePropertyName:'$($parmInfo.ResourcePropertyName)' exist in the configuration."
        }

        Write-Verbose "Updating configuration parameter for $resourceId ..."
        $resourcesInMofDocument | ForEach-Object {
            if (($_.CimInstanceProperties.Name -contains 'ResourceID') -and ($_.CimInstanceProperties['ResourceID'].Value -eq $resourceId)) {
                $item = $_.CimInstanceProperties.Item($parmInfo.ResourcePropertyName)
                $item.Value = $parmInfo.ResourcePropertyValue
            }
        }
    }

    Write-Verbose "Saving configuration file '$Path' with updated parameters ..."
    $content = ""
    for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++) {
        $resourceClassName = $resourcesInMofDocument[$i].CimSystemProperties.ClassName
        $content += "instance of $resourceClassName"

        if ($resourceClassName -ne 'OMI_ConfigurationDocument') {
            $content += ' as $' + "$resourceClassName$i"
        }
        $content += "`n{`n"
        $resourcesInMofDocument[$i].CimInstanceProperties | ForEach-Object {
            $content += " $($_.Name)"
            if ($_.CimType -eq 'StringArray') {
                $content += " = {""$($_.Value -replace '[""\\]','\$&')""}; `n"
            }
            else {
                $content += " = ""$($_.Value -replace '[""\\]','\$&')""; `n"
            }
        }
        $content += "};`n" ;
    }

    $content | Out-File $Path
}

function Get-GuestConfigurationMofContent {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    Write-Verbose "Parsing Configuration document '$Path'"
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    # Set the profile path for Chef resource
    $resourcesInMofDocument | ForEach-Object {
        if ($_.CimClass.CimClassName -eq 'MSFT_ChefInSpecResource') {
            $profilePath = "$Name/Modules/$($_.Name)"
            $item = $_.CimInstanceProperties.Item('GithubPath')
            if ($item -eq $null) {
                $item = [Microsoft.Management.Infrastructure.CimProperty]::Create('GithubPath', $profilePath, [Microsoft.Management.Infrastructure.CimFlags]::Property)                      
                $_.CimInstanceProperties.Add($item) 
            }
            else {
                $item.Value = $profilePath
            }
        }
    }

    return $resourcesInMofDocument
}

function Save-GuestConfigurationMofDocument {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $SourcePath,

        [Parameter(Mandatory = $true)]
        [String]
        $DestinationPath
    )

    $resourcesInMofDocument = Get-GuestConfigurationMofContent -Name $Name -Path $SourcePath

    # if mof contains Chef resource
    if ($resourcesInMofDocument.CimSystemProperties.ClassName -contains 'MSFT_ChefInSpecResource') {
        Write-Verbose "Serialize DSC document to $DestinationPath path ..."
        $content = ''
        for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++) {
            $resourceClassName = $resourcesInMofDocument[$i].CimSystemProperties.ClassName
            $content += "instance of $resourceClassName"

            if ($resourceClassName -ne 'OMI_ConfigurationDocument') {
                $content += ' as $' + "$resourceClassName$i"
            }
            $content += "`n{`n"
            $resourcesInMofDocument[$i].CimInstanceProperties | ForEach-Object {
                $content += " $($_.Name)"
                if ($_.CimType -eq 'StringArray') {
                    $content += " = {""$($_.Value -replace '[""\\]','\$&')""}; `n"
                }
                else {
                    $content += " = ""$($_.Value -replace '[""\\]','\$&')""; `n"
                }
            }
            $content += "};`n" ;
        }

        $content | Out-File $DestinationPath
    }
    else {
        Write-Verbose "Copy DSC document to $DestinationPath path ..."
        Copy-Item $SourcePath $DestinationPath
    }
}

function Format-Json {
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Json
    )

    $indent = 0
    $jsonLines = $Json -Split '\n'
    $formattedLines = @()
    $previousLine = ''

    foreach ($line in $jsonLines) {
        $skipAddingLine = $false
        if ($line -match '^\s*\}\s*' -or $line -match '^\s*\]\s*') {
            # This line contains  ] or }, decrement the indentation level
            $indent--
        }

        $formattedLine = (' ' * $indent * 4) + $line.TrimStart().Replace(':  ', ': ')

        if ($line -match '\s*".*"\s*:\s*\[' -or $line -match '\s*".*"\s*:\s*\{' -or $line -match '^\s*\{\s*' -or $line -match '^\s*\[\s*') {
            # This line contains [ or {, increment the indentation level
            $indent++
        }

        if ($previousLine.Trim().EndsWith("{")) {
            if ($formattedLine.Trim() -in @("}", "},")) {
                $newLine = "$($previousLine.TrimEnd())$($formattedLine.Trim())"
                #Write-Verbose -Message "FOUND SHORTENED LINE: $newLine"
                $formattedLines[($formattedLines.Count - 1)] = $newLine
                $previousLine = $newLine
                $skipAddingLine = $true
            }
        }

        if ($previousLine.Trim().EndsWith("[")) {
            if ($formattedLine.Trim() -in @("]", "],")) {
                $newLine = "$($previousLine.TrimEnd())$($formattedLine.Trim())"
                #Write-Verbose -Message "FOUND SHORTENED LINE: $newLine"
                $formattedLines[($formattedLines.Count - 1)] = $newLine
                $previousLine = $newLine
                $skipAddingLine = $true
            }
        }

        if (-not $skipAddingLine -and -not [String]::IsNullOrWhiteSpace($formattedLine)) {
            $previousLine = $formattedLine
            $formattedLines += $formattedLine
        }
    }

    $formattedJson = $formattedLines -join "`n"
    return $formattedJson
}

function New-GuestConfigurationDeployPolicyDefinition {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FileName,

        [Parameter(Mandatory = $true)]
        [String]
        $FolderPath,

        [Parameter(Mandatory = $true)]
        [String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [String]
        $Description,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationName,

        [Parameter(Mandatory = $true)]
        [version]
        $ConfigurationVersion,

        [Parameter(Mandatory = $true)]
        [String]
        $ContentUri,

        [Parameter(Mandatory = $true)]
        [String]
        $ContentHash,

        [Parameter(Mandatory = $true)]
        [String]
        $ReferenceId,

        [Parameter()]
        [Hashtable[]]
        $ParameterInfo,

        [Parameter()]
        [String]
        $Guid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [String]
        $Platform,

        [Parameter()]
        [bool]
        $UseCertificateValidation = $false,

        [Parameter()]
        [String]
        $Category = 'Guest Configuration',

        [Parameter()]
        [Hashtable[]]
        $Tag
    )

    if (-not [String]::IsNullOrEmpty($Guid)) {
        $deployPolicyGuid = $Guid
    }
    else {
        $deployPolicyGuid = [Guid]::NewGuid()
    }

    $filePath = Join-Path -Path $FolderPath -ChildPath $FileName

    $deployPolicyContentHashtable = [Ordered]@{
        properties = [Ordered]@{
            displayName = $DisplayName
            policyType  = 'Custom'
            mode        = 'Indexed'
            description = $Description
            metadata    = [Ordered]@{
                category          = $Category
                requiredProviders = @(
                    'Microsoft.GuestConfiguration'
                )
            }
        }
    }

    $policyRuleHashtable = [Ordered]@{
        if   = [Ordered]@{
            anyOf = @(
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            field  = 'type'
                            equals = "Microsoft.Compute/virtualMachines"
                        }
                    )
                },
                [Ordered]@{
                    allOf = @(,
                        [Ordered]@{
                            field  = "type"
                            equals = "Microsoft.HybridCompute/machines"
                        }
                    )
                }
            )
        }
        then = [Ordered]@{
            effect  = 'deployIfNotExists'
            details = [Ordered]@{
                type              = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
                name              = $ConfigurationName
                roleDefinitionIds = @('/providers/microsoft.authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c')
            }
        }
    }

    $deploymentHashtable = [Ordered]@{
        properties = [Ordered]@{
            mode       = 'incremental'
            parameters = [Ordered]@{
                vmName            = [Ordered]@{
                    value = "[field('name')]"
                }
                location          = [Ordered]@{
                    value = "[field('location')]"
                }
                type              = [Ordered]@{
                    value = "[field('type')]"
                }
                configurationName = [Ordered]@{
                    value = $ConfigurationName
                }
                contentUri        = [Ordered]@{
                    value = $ContentUri
                }
                contentHash       = [Ordered]@{
                    value = $ContentHash
                }
            }
            template   = [Ordered]@{
                '$schema'      = 'https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#'
                contentVersion = '1.0.0.0'
                parameters     = [Ordered]@{
                    vmName            = [Ordered]@{
                        type = 'string'
                    }
                    location          = [Ordered]@{
                        type = 'string'
                    }
                    type              = [Ordered]@{
                        type = 'string'
                    }
                    configurationName = [Ordered]@{
                        type = 'string'
                    }
                    contentUri        = [Ordered]@{
                        type = 'string'
                    }
                    contentHash       = [Ordered]@{
                        type = 'string'
                    }
                }
                resources      = @()
            }
        }
    }

    $guestConfigurationAssignmentHashtable = @(
        [Ordered]@{
            apiVersion = '2018-11-20'
            type       = 'Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments'
            name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/', parameters('configurationName'))]"
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                guestConfiguration = [Ordered]@{
                    name        = "[parameters('configurationName')]"
                    contentUri  = "[parameters('contentUri')]"
                    contentHash = "[parameters('contentHash')]"
                    version     = $ConfigurationVersion.ToString()
                }
            }
            condition  = "[equals(toLower(parameters('type')), toLower('Microsoft.Compute/virtualMachines'))]"
        },
        [Ordered]@{
            apiVersion = '2018-11-20'
            type       = 'Microsoft.HybridCompute/machines/providers/guestConfigurationAssignments'
            name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/', parameters('configurationName'))]"
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                guestConfiguration = [Ordered]@{
                    name        = "[parameters('configurationName')]"
                    contentUri  = "[parameters('contentUri')]"
                    contentHash = "[parameters('contentHash')]"
                    version     = $ConfigurationVersion.ToString()
                }
            }
            condition  = "[equals(toLower(parameters('type')), toLower('microsoft.hybridcompute/machines'))]"
        }
    )

    if ($Platform -ieq 'Windows') {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in    = @(
                            'esri',
                            'incredibuild',
                            'MicrosoftDynamicsAX',
                            'MicrosoftSharepoint',
                            'MicrosoftVisualStudio',
                            'MicrosoftWindowsDesktop',
                            'MicrosoftWindowsServerHPCPack'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'MicrosoftWindowsServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'MicrosoftSQLServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageOffer'
                                notLike = 'SQL2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'dsvm-windows'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'standard-data-science-vm',
                                    'windows-data-science-vm'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'batch'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'rendering-windows2016'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'cis-windows-server-201*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'pivotal'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'bosh-windows-server*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloud-infrastructure-services'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'ad*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                anyOf = @(
                                    [Ordered]@{ 
                                        field  = 'Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration'
                                        exists = 'true'
                                    },
                                    [Ordered]@{
                                        field = 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                                        like  = 'Windows*'
                                    }
                                )
                            },
                            [Ordered]@{ 
                                anyOf = @(
                                    [Ordered]@{ 
                                        field  = 'Microsoft.Compute/imageSKU'
                                        exists = 'false'
                                    },
                                    [Ordered]@{
                                        allOf = @(
                                            [Ordered]@{ 
                                                field   = 'Microsoft.Compute/imageSKU'
                                                notLike = '2008*'
                                            },
                                            [Ordered]@{
                                                field   = 'Microsoft.Compute/imageOffer'
                                                notLike = 'SQL2008*'
                                            }
                                        )
                                    }
                                )
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'windows*'
            }
        )

        $guestConfigurationExtensionHashtable = [Ordered]@{
            apiVersion = '2015-05-01-preview'
            name       = "[concat(parameters('vmName'), '/AzurePolicyforWindows')]"
            type       = 'Microsoft.Compute/virtualMachines/extensions'
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                publisher               = 'Microsoft.GuestConfiguration'
                type                    = 'ConfigurationforWindows'
                typeHandlerVersion      = '1.1'
                autoUpgradeMinorVersion = $true
                settings                = @{ }
                protectedSettings       = @{ }
            }
            dependsOn  = @(
                "[concat('Microsoft.Compute/virtualMachines/',parameters('vmName'),'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/',parameters('configurationName'))]"
            )
            condition  = "[equals(toLower(parameters('type')), toLower('Microsoft.Compute/virtualMachines'))]"
        }
    }
    elseif ($Platform -ieq 'Linux') {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = 'Microsoft.Compute/imagePublisher'
                        in    = @(
                            'microsoft-aks',
                            'qubole-inc',
                            'datastax',
                            'couchbase',
                            'scalegrid',
                            'checkpoint',
                            'paloaltonetworks'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'OpenLogic'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'CentOS*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Oracle'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Oracle-Linux'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'RHEL',
                                    'RHEL-HA'
                                    'RHEL-SAP',
                                    'RHEL-SAP-APPS',
                                    'RHEL-SAP-HA',
                                    'RHEL-SAP-HANA'
                                )
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'osa',
                                    'rhel-byos'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'cis-centos-7-l1',
                                    'cis-centos-7-v2-1-1-l1'
                                    'cis-centos-8-l1',
                                    'cis-debian-linux-8-l1',
                                    'cis-debian-linux-9-l1',
                                    'cis-nginx-centos-7-v1-1-0-l1',
                                    'cis-oracle-linux-7-v2-0-0-l1',
                                    'cis-oracle-linux-8-l1',
                                    'cis-postgresql-11-centos-linux-7-level-1',
                                    'cis-rhel-7-l2',
                                    'cis-rhel-7-v2-2-0-l1',
                                    'cis-rhel-8-l1',
                                    'cis-suse-linux-12-v2-0-0-l1',
                                    'cis-ubuntu-linux-1604-v1-0-0-l1',
                                    'cis-ubuntu-linux-1804-l1'

                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'credativ'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Debian'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '7*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Suse'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'SLES*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '11*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Canonical'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'UbuntuServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '12*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'linux-data-science-vm-ubuntu',
                                    'azureml'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-centos-os'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-altus-centos-os'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'linux*'
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "linux*"
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'linux*'
            }
        )

        $guestConfigurationExtensionHashtable = [Ordered]@{
            apiVersion = '2015-05-01-preview'
            name       = "[concat(parameters('vmName'), '/AzurePolicyforLinux')]"
            type       = 'Microsoft.Compute/virtualMachines/extensions'
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                publisher               = 'Microsoft.GuestConfiguration'
                type                    = 'ConfigurationforLinux'
                typeHandlerVersion      = '1.0'
                autoUpgradeMinorVersion = $true
            }
            dependsOn  = @(
                "[concat('Microsoft.Compute/virtualMachines/',parameters('vmName'),'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/',parameters('configurationName'))]"
            )
            condition  = "[equals(toLower(parameters('type')), toLower('Microsoft.Compute/virtualMachines'))]"
        }
    }
    else {
        throw "The specified platform '$Platform' is not currently supported by this script."
    }

    # if there is atleast one tag
    if ($PSBoundParameters.ContainsKey('Tag') -AND $null -ne $Tag) {
        # capture existing 'anyOf' section
        $anyOf = $policyRuleHashtable['if']
        # replace with new 'allOf' at top order
        $policyRuleHashtable['if'] = [Ordered]@{
            allOf = @(
            )
        }
        # add tags section under new 'allOf'
        $policyRuleHashtable['if']['allOf'] += [Ordered]@{
            allOf = @(
            )
        }
        # re-insert 'anyOf' under new 'allOf' after tags 'allOf'
        $policyRuleHashtable['if']['allOf'] += $anyOf
        # add each tag individually to tags 'allOf'
        for ($i = 0; $i -lt $Tag.count; $i++) {
            # if there is atleast one tag
            if (-not [string]::IsNullOrEmpty($Tag[$i].Keys)) {
                $policyRuleHashtable['if']['allOf'][0]['allOf'] += [Ordered]@{
                    field  = "tags.$($Tag[$i].Keys)"
                    equals = "$($Tag[$i].Values)"
                }
            }
        }
    }

    $existenceConditionList = @()
    # Handle adding parameters if needed
    if ($null -ne $ParameterInfo -and $ParameterInfo.Count -gt 0) {
        $parameterValueConceatenatedStringList = @()

        if (-not $deployPolicyContentHashtable['properties'].Contains('parameters')) {
            $deployPolicyContentHashtable['properties']['parameters'] = [Ordered]@{ }
        }

        if (-not $guestConfigurationAssignmentHashtable['properties']['guestConfiguration'].Contains('configurationParameter')) {
            $guestConfigurationAssignmentHashtable['properties']['guestConfiguration']['configurationParameter'] = @()
        }

        foreach ($currentParameterInfo in $ParameterInfo) {
            $deployPolicyContentHashtable['properties']['parameters'] += [Ordered]@{
                $currentParameterInfo.ReferenceName = [Ordered]@{
                    type     = $currentParameterInfo.Type
                    metadata = [Ordered]@{
                        displayName = $currentParameterInfo.DisplayName
                    }
                }
            }

            if ($currentParameterInfo.ContainsKey('Description')) {
                $deployPolicyContentHashtable['properties']['parameters'][$currentParameterInfo.ReferenceName]['metadata']['description'] = $currentParameterInfo['Description']
            }

            if ($currentParameterInfo.ContainsKey('DefaultValue')) {
                $deployPolicyContentHashtable['properties']['parameters'][$currentParameterInfo.ReferenceName] += [Ordered]@{
                    defaultValue = $currentParameterInfo.DefaultValue
                }
            }

            if ($currentParameterInfo.ContainsKey('AllowedValues')) {
                $deployPolicyContentHashtable['properties']['parameters'][$currentParameterInfo.ReferenceName] += [Ordered]@{
                    allowedValues = $currentParameterInfo.AllowedValues
                }
            }

            if ($currentParameterInfo.ContainsKey('DeploymentValue')) {
                $deploymentHashtable['properties']['parameters'] += [Ordered]@{
                    $currentParameterInfo.ReferenceName = [Ordered]@{
                        value = $currentParameterInfo.DeploymentValue
                    }
                }
            }
            else {
                $deploymentHashtable['properties']['parameters'] += [Ordered]@{
                    $currentParameterInfo.ReferenceName = [Ordered]@{
                        value = "[parameters('$($currentParameterInfo.ReferenceName)')]"
                    }
                }
            }

            $deploymentHashtable['properties']['template']['parameters'] += [Ordered]@{
                $currentParameterInfo.ReferenceName = [Ordered]@{
                    type = $currentParameterInfo.Type
                }
            }

            $configurationParameterName = "$($currentParameterInfo.MofResourceReference);$($currentParameterInfo.MofParameterName)"

            if ($currentParameterInfo.ContainsKey('ConfigurationValue')) {
                $configurationParameterValue = $currentParameterInfo.ConfigurationValue

                if ($currentParameterInfo.ConfigurationValue.StartsWith('[') -and $currentParameterInfo.ConfigurationValue.EndsWith(']')) {
                    $configurationParameterStringValue = $currentParameterInfo.ConfigurationValue.Substring(1, $currentParameterInfo.ConfigurationValue.Length - 2)
                }
                else {
                    $configurationParameterStringValue = "'$($currentParameterInfo.ConfigurationValue)'"
                }
            }
            else {
                $configurationParameterValue = "[parameters('$($currentParameterInfo.ReferenceName)')]"
                $configurationParameterStringValue = "parameters('$($currentParameterInfo.ReferenceName)')"
            }

            $guestConfigurationAssignmentHashtable['properties']['guestConfiguration']['configurationParameter'] += [Ordered]@{
                name  = $configurationParameterName
                value = $configurationParameterValue
            }

            $currentParameterValueConcatenatedString = "'$configurationParameterName', '=', $configurationParameterStringValue"
            $parameterValueConceatenatedStringList += $currentParameterValueConcatenatedString
        }

        $allParameterValueConcantenatedString = $parameterValueConceatenatedStringList -join ", ',', "
        $parameterExistenceConditionEqualsValue = "[base64(concat($allParameterValueConcantenatedString))]"

        $existenceConditionList += [Ordered]@{
            field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/parameterHash'
            equals = $parameterExistenceConditionEqualsValue
        }
    }

    $existenceConditionList += [Ordered]@{
        field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/contentHash'
        equals = "$ContentHash"
    }

    $policyRuleHashtable['then']['details']['existenceCondition'] = [Ordered]@{
        allOf = $existenceConditionList
    }
    $policyRuleHashtable['then']['details']['deployment'] = $deploymentHashtable

    $policyRuleHashtable['then']['details']['deployment']['properties']['template']['resources'] += $guestConfigurationAssignmentHashtable
    
    $systemAssignedHashtable = [Ordered]@{
        apiVersion = '2019-07-01'
        type       = 'Microsoft.Compute/virtualMachines'
        identity   = [Ordered]@{
            type = 'SystemAssigned'
        }
        name       = "[parameters('vmName')]"
        location   = "[parameters('location')]"
        condition  = "[equals(toLower(parameters('type')), toLower('Microsoft.Compute/virtualMachines'))]"
    }    
    
    $policyRuleHashtable['then']['details']['deployment']['properties']['template']['resources'] += $systemAssignedHashtable
    
    $policyRuleHashtable['then']['details']['deployment']['properties']['template']['resources'] += $guestConfigurationExtensionHashtable

    $deployPolicyContentHashtable['properties']['policyRule'] = $policyRuleHashtable

    $deployPolicyContentHashtable += [Ordered]@{
        id   = "/providers/Microsoft.Authorization/policyDefinitions/$deployPolicyGuid"
        name = $deployPolicyGuid
    }

    $deployPolicyContent = ConvertTo-Json -InputObject $deployPolicyContentHashtable -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }
    $formattedDeployPolicyContent = Format-Json -Json $deployPolicyContent

    if (Test-Path -Path $filePath) {
        Write-Error -Message "A file at the policy destination path '$filePath' already exists. Please remove this file or specify a different destination path."
    }
    else {
        $null = New-Item -Path $filePath -ItemType 'File' -Value $formattedDeployPolicyContent
    }

    return $deployPolicyGuid
}

<#
    .SYNOPSIS
        Creates a new audit policy definition for a guest configuration policy.
#>
function New-GuestConfigurationAuditPolicyDefinition {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FileName,

        [Parameter(Mandatory = $true)]
        [String]
        $FolderPath,

        [Parameter(Mandatory = $true)]
        [String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [String]
        $Description,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationName,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationVersion,

        [Parameter(Mandatory = $true)]
        [String]
        $ReferenceId,

        [Parameter()]
        [Hashtable[]]
        $ParameterInfo,

        [Parameter()]
        [String]
        $ContentUri,

        [Parameter()]
        [String]
        $ContentHash,

        [Parameter()]
        [bool]
        $UseCertificateValidation = $false,

        [Parameter(Mandatory = $false)]
        [String]
        $Category = 'Guest Configuration',

        [Parameter()]
        [String]
        $Guid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [String]
        $Platform,

        [Parameter()]
        [Hashtable[]]
        $Tag
    )

    if (-not [String]::IsNullOrEmpty($Guid)) {
        $auditPolicyGuid = $Guid
    }
    else {
        $auditPolicyGuid = [Guid]::NewGuid()
    }

    $filePath = Join-Path -Path $FolderPath -ChildPath $FileName
    $ParameterMapping = @{ }
    $ParameterDefinitions = @{ }
    $auditPolicyContentHashtable = [Ordered]@{ }
    
    if ($null -ne $ParameterInfo) {
        $ParameterMapping = Get-ParameterMappingForAINE $ParameterInfo
        $ParameterDefinitions = Get-ParameterDefinitionsAINE $ParameterInfo
    }
    
    $ParameterDefinitions['IncludeArcMachines'] += [Ordered]@{
        Type            = "String"
        Metadata        = [Ordered]@{
            DisplayName     = 'Include Arc connected servers'
            Description     = 'By selecting this option, you agree to be charged monthly per Arc connected machine.'
        }
        AllowedValues   = @('True','False')
        DefaultValue    = 'False'
    }
    
    $auditPolicyContentHashtable = [Ordered]@{
        properties = [Ordered]@{
            displayName = $DisplayName
            policyType  = 'Custom'
            mode        = 'All'
            description = $Description
            metadata    = [Ordered]@{
                category           = $Category
                guestConfiguration = [Ordered]@{
                    name                   = $ConfigurationName
                    version                = $ConfigurationVersion
                    contentType            = "Custom"
                    contentUri             = $ContentUri
                    contentHash            = $ContentHash
                    configurationParameter = $ParameterMapping
                }
            }
            parameters  = $ParameterDefinitions
            
        }
        id         = "/providers/Microsoft.Authorization/policyDefinitions/$auditPolicyGuid"
        name       = $auditPolicyGuid
    }
     

    $policyRuleHashtable = [Ordered]@{
        if   = [Ordered]@{
            anyOf = @(
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            field  = 'type'
                                    equals = "Microsoft.Compute/virtualMachines"
                        }
                    )
                },
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            value = "[parameters('IncludeArcMachines')]"
                            equals = "true"
                        },
                        [Ordered]@{
                            field = "type"
                            equals = "Microsoft.HybridCompute/machines"
                        }
                    )
                }
            )
        }
        then = [Ordered]@{
            effect  = 'auditIfNotExists'
            details = [Ordered]@{
                type = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
                name = $ConfigurationName
            }
        }
    }

    if ($Platform -ieq 'Windows')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in = @(
                            'esri',
                            'incredibuild',
                            'MicrosoftDynamicsAX',
                            'MicrosoftSharepoint',
                            'MicrosoftVisualStudio',
                            'MicrosoftWindowsDesktop',
                            'MicrosoftWindowsServerHPCPack'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'MicrosoftWindowsServer'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageSKU"
                                notLike = '2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'MicrosoftSQLServer'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                notLike = 'SQL2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imageOffer"
                                equals = 'dsvm-windows'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imageOffer"
                                in = @(
                                    'standard-data-science-vm',
                                    'windows-data-science-vm'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'batch'
                            },
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imageOffer"
                                equals = 'rendering-windows2016'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like = 'cis-windows-server-201*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'pivotal'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like = 'bosh-windows-server*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'cloud-infrastructure-services'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like = 'ad*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                anyOf = @(
                                    [Ordered]@{ 
                                        field = "Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration"
                                        exists = 'true'
                                    },
                                    [Ordered]@{
                                        field = "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"
                                        like = 'Windows*'
                                    }
                                )
                            },
                            [Ordered]@{ 
                                anyOf = @(
                                    [Ordered]@{ 
                                        field = "Microsoft.Compute/imageSKU"
                                        exists = 'false'
                                    },
                                    [Ordered]@{
                                        allOf = @(
                                            [Ordered]@{ 
                                                field = "Microsoft.Compute/imageSKU"
                                                notLike = '2008*'
                                            },
                                            [Ordered]@{
                                                field = "Microsoft.Compute/imageOffer"
                                                notLike = 'SQL2008*'
                            }
                        )
                    }
                )
            }
        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like = "windows*"
            }
        )
    }
    elseif ($Platform -ieq 'Linux')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in = @(
                            'microsoft-aks',
                            'qubole-inc',
                            'datastax',
                            'couchbase',
                            'scalegrid',
                            'checkpoint',
                            'paloaltonetworks'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imagePublisher"
                                equals = 'OpenLogic'
                            },
                            [Ordered]@{ 
                                field = "Microsoft.Compute/imageOffer"
                                like = 'CentOS*'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageSKU"
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'Oracle'
                            },
                            [Ordered]@{ 
                                field  = "Microsoft.Compute/imageOffer"
                                equals = 'Oracle-Linux'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageSKU"
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'RHEL',
                                    'RHEL-HA'
                                    'RHEL-SAP',
                                    'RHEL-SAP-APPS',
                                    'RHEL-SAP-HA',
                                    'RHEL-SAP-HANA'
                                )
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'osa',
                                    'rhel-byos'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'cis-centos-7-l1',
                                    'cis-centos-7-v2-1-1-l1'
                                    'cis-centos-8-l1',
                                    'cis-debian-linux-8-l1',
                                    'cis-debian-linux-9-l1',
                                    'cis-nginx-centos-7-v1-1-0-l1',
                                    'cis-oracle-linux-7-v2-0-0-l1',
                                    'cis-oracle-linux-8-l1',
                                    'cis-postgresql-11-centos-linux-7-level-1',
                                    'cis-rhel-7-l2',
                                    'cis-rhel-7-v2-2-0-l1',
                                    'cis-rhel-8-l1',
                                    'cis-suse-linux-12-v2-0-0-l1',
                                    'cis-ubuntu-linux-1604-v1-0-0-l1',
                                    'cis-ubuntu-linux-1804-l1'

                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'credativ'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Debian'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '7*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Suse'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'SLES*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '11*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Canonical'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'UbuntuServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '12*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'linux-data-science-vm-ubuntu',
                                    'azureml'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-centos-os'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-altus-centos-os'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{ 
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{ 
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'linux*'
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like = "linux*"
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'linux*'
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "linux*"
            }
        )
    }
    else
    {
        throw "The specified platform '$Platform' is not currently supported by this script."
    }

    # if there is atleast one tag
    if ($PSBoundParameters.ContainsKey('Tag') -AND $null -ne $Tag) {
        # capture existing 'anyOf' section
        $anyOf = $policyRuleHashtable['if']
        # replace with new 'allOf' at top order
        $policyRuleHashtable['if'] = [Ordered]@{
            allOf = @(
            )
        }
        # add tags section under new 'allOf'
        $policyRuleHashtable['if']['allOf'] += [Ordered]@{
            allOf = @(
            )
        }
        # re-insert 'anyOf' under new 'allOf' after tags 'allOf'
        $policyRuleHashtable['if']['allOf'] += $anyOf
        # add each tag individually to tags 'allOf'
        for($i = 0; $i -lt $Tag.count; $i++) {
            # if there is atleast one tag
            if (-not [string]::IsNullOrEmpty($Tag[$i].Keys)) {
                $policyRuleHashtable['if']['allOf'][0]['allOf'] += [Ordered]@{
                    field = "tags.$($Tag[$i].Keys)"
                    equals = "$($Tag[$i].Values)"
                }
            }
        }
    }

    $existenceConditionList = [Ordered]@{
        allOf = [System.Collections.ArrayList]@()
    }
    $existenceConditionList['allOf'].Add([Ordered]@{
            field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus'
            equals = 'Compliant'
        })
    
    if ($null -ne $ParameterInfo) {
        $parametersExistenceCondition = Get-GuestConfigurationAssignmentParametersExistenceConditionSection -ParameterInfo $ParameterInfo
        $existenceConditionList['allOf'].Add($parametersExistenceCondition)
    }

    $policyRuleHashtable['then']['details']['existenceCondition'] = $existenceConditionList

    $auditPolicyContentHashtable['properties']['policyRule'] = $policyRuleHashtable

    $auditPolicyContent = ConvertTo-Json -InputObject $auditPolicyContentHashtable -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }
    $formattedAuditPolicyContent = Format-Json -Json $auditPolicyContent

    if (Test-Path -Path $filePath) {
        Write-Error -Message "A file at the policy destination path '$filePath' already exists. Please remove this file or specify a different destination path."
    }
    else {
        $null = New-Item -Path $filePath -ItemType 'File' -Value $formattedAuditPolicyContent
    }

    return $auditPolicyGuid
}

<#
    .SYNOPSIS
        Creates a new policy for guest configuration.
#>
function New-GuestConfigurationPolicyDefinition {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PolicyFolderPath,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $AuditIfNotExistsInfo
    )

    if (Test-Path -Path $PolicyFolderPath) {
        $null = Remove-Item -Path $PolicyFolderPath -Force -Recurse -ErrorAction 'SilentlyContinue'
    }

    $null = New-Item -Path $PolicyFolderPath -ItemType 'Directory'
    
    foreach ($currentAuditPolicyInfo in $AuditIfNotExistsInfo) {
        $currentAuditPolicyInfo['FolderPath'] = $PolicyFolderPath
        New-GuestConfigurationAuditPolicyDefinition @currentAuditPolicyInfo
    }
}

function New-CustomGuestConfigPolicy {
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PolicyFolderPath,
        
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $AuditIfNotExistsInfo
    )

    $existingPolicies = Get-AzPolicyDefinition
    
    $existingAuditPolicy = $existingPolicies | Where-Object { ($_.Properties.PSObject.Properties.Name -contains 'displayName') -and ($_.Properties.displayName -eq $AuditIfNotExistsInfo.DisplayName) }
    if ($null -ne $existingAuditPolicy) {
        Write-Verbose -Message "Found policy with name '$($existingAuditPolicy.Properties.displayName)' and guid '$($existingAuditPolicy.Name)'..."
        $AuditIfNotExistsInfo['Guid'] = $existingAuditPolicy.Name
    }

    New-GuestConfigurationPolicyDefinition @PSBoundParameters
}

<#
    .SYNOPSIS
        Retrieves a policy section check for the existence of a Guest Configuration Assignment with the specified parameters.
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParametersExistenceConditionSection -ParameterInfo $parameterInfo
#>
function Get-GuestConfigurationAssignmentParametersExistenceConditionSection
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable[]]
        $ParameterInfo
    )
    $parameterValueConceatenatedStringList = @()
    foreach ($currentParameterInfo in $ParameterInfo)
    {
        $assignmentParameterName = Get-GuestConfigurationAssignmentParameterName -ParameterInfo $currentParameterInfo
        $assignmentParameterStringValue = Get-GuestConfigurationAssignmentParameterStringValue -ParameterInfo $currentParameterInfo
        $currentParameterValueConcatenatedString = "'$assignmentParameterName', '=', $assignmentParameterStringValue"
        $parameterValueConceatenatedStringList += $currentParameterValueConcatenatedString
    }
    $allParameterValueConcantenatedString = $parameterValueConceatenatedStringList -join ", ',', "
    $parameterExistenceConditionEqualsValue = "[base64(concat($allParameterValueConcantenatedString))]"
    $existenceConditionHashtable = [Ordered]@{
        field = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/parameterHash'
        equals = $parameterExistenceConditionEqualsValue
    }
    return $existenceConditionHashtable
}

<#
    .SYNOPSIS
        Retrieves the name of a Guest Configuration Assignment parameter correctly formatted to be passed to the Guest Configuration Assignment.
    .PARAMETER ParameterInfo
        A single hashtable indicating the necessary parameter info from which to retrieve the parameter name.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParameterName -ParameterInfo $currentParameterInfo
#>
function Get-GuestConfigurationAssignmentParameterName
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter()]
        [Hashtable]
        $ParameterInfo
    )
    $assignmentParameterName = "$($ParameterInfo.MofResourceReference);$($ParameterInfo.MofParameterName)"
    return $assignmentParameterName
}

<#
    .SYNOPSIS
        Retrieves the string value of a Guest Configuration Assignment parameter correctly formatted to be passed to the Guest Configuration Assignment as part of the parameter hash.
    .PARAMETER ParameterInfo
        A single hashtable indicating the necessary parameter info from which to retrieve the parameter string value.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParameterStringValue -ParameterInfo $currentParameterInfo
#>
function Get-GuestConfigurationAssignmentParameterStringValue
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter()]
        [Hashtable]
        $ParameterInfo
    )
    if ($ParameterInfo.ContainsKey('ConfigurationValue'))
    {
        if ($ParameterInfo.ConfigurationValue.StartsWith('[') -and $ParameterInfo.ConfigurationValue.EndsWith(']'))
        {
            $assignmentParameterStringValue = $ParameterInfo.ConfigurationValue.Substring(1, $ParameterInfo.ConfigurationValue.Length - 2)
        }
        else
        {
            $assignmentParameterStringValue = "'$($ParameterInfo.ConfigurationValue)'"
        }
    }
    else
    {
        $assignmentParameterStringValue = "parameters('$($ParameterInfo.ReferenceName)')"
    }
    return $assignmentParameterStringValue
}

<#
    .SYNOPSIS
        Define the policy parameter mapping to the parameters of the MOF file. 
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
#>
function  Get-ParameterMappingForAINE
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]   
        [array]     
        $ParameterInfo
    )
    $paramMapping =  @{}
    foreach($item in $ParameterInfo)
    {
        $paramMapping[$item.ReferenceName] = ("{0};{1}" -f $item.MofResourceReference, $item.MofParameterName)
    }
    return $paramMapping
}

<#
    .SYNOPSIS
        Define the parmameters of AINE policy for AuditWithout DINE scenario.
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
#>
function Get-ParameterDefinitionsAINE
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]   
        [Hashtable[]]$ParameterInfo
    )
    
    $paramDefinition = [Ordered]@{}
    foreach($item in $ParameterInfo)
    {
        $paramDefinition[$($item.ReferenceName)] = @{
                type = $item.Type 
                metadata = [Ordered]@{
                    displayName = $item.DisplayName
                    description = $item.Description
                }
         }
         if ($item.ContainsKey('AllowedValues'))
         {
            $paramDefinition[$($item.ReferenceName)]['allowedValues'] = $item.AllowedValues
         }
         if ($item.ContainsKey('DefaultValue'))
         {
            $paramDefinition[$($item.ReferenceName)]['defaultValue'] = $item.DefaultValue  
         }
    }
    return $paramDefinition
}

# SIG # Begin signature block
# MIIjkgYJKoZIhvcNAQcCoIIjgzCCI38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDO4ON6O8Z4INOf
# QQQTHkQRRx14AqPWnrZKPkJbML2GXqCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVZzCCFWMCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgMhur152Y
# aET0tEVDrQjiOTUghl+dbVz9Zj/sT27dSNUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBs6OB7GAXEBh370zw3T6Gtf4/f0UNPU+yePYhhUeVk
# uoCXZHJvQsrALs8eitYDEpRmpbAJ1OAIj1smSTHLGSzIYkcbIjE/Hg+ZF5Ipvuv7
# RJZtv00pSboB63AGDsHPAXIgwLUFeXtqy6ETw4uq8uBU7d2IusJomIHcXfoLE6vR
# qJ1FHy7sZG40KEczYd+MnvLXeSzQu2p/XNVV420+Pf1qebzevIjSXP0RcktD9Mn7
# A+n1UUq1HOFSXQ592o0q6w29J0lhs9y0juHlLPZqvFcJRWLZTRCqdHXzfyq83XBe
# zMoOl3ANBgHrzKPJxotDcSVYi4+xG9/g3gnez8xS5b+roYIS8TCCEu0GCisGAQQB
# gjcDAwExghLdMIIS2QYJKoZIhvcNAQcCoIISyjCCEsYCAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIEpyxLqlNVed8AF1DXGzhQVmqCPvU5f4JUCYssuo
# 6AkFAgZgGeHpE2IYEzIwMjEwMjAzMTUxOTM2Ljk3N1owBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCDkQwggT1MIID3aADAgECAhMzAAABK5PQ7Y4K9/BHAAAA
# AAErMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTE5MTIxOTAxMTUwMloXDTIxMDMxNzAxMTUwMlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJG
# LUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJb6i4/AWVpXjQAludgA
# NHARSFyzEjltq7Udsw5sSZo68N8oWkL+QKz842RqIiggTltm6dHYFcmB1YRRqMdX
# 6Y7gJT9Sp8FVI10FxGF5I6d6BtQCjDBc2/s1ih0E111SANl995D8FgY8ea5u1nqE
# omlCBbjdoqYy3APET2hABpIM6hcwIaxCvd+ugmJnHSP+PxI/8RxJh8jT/GFRzkL1
# wy/kD2iMl711Czg3DL/yAHXusqSw95hZmW2mtL7HNvSz04rifjZw3QnYPwIi46CS
# i34Kr9p9dB1VV7++Zo9SmgdjmvGeFjH2Jth3xExPkoULaWrvIbqcpOs9E7sAUJTB
# sB0CAwEAAaOCARswggEXMB0GA1UdDgQWBBQi72h0uFIDuXSWYWPz0HeSiMCTBTAf
# BgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0
# YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBnP/nYpaY+bpVs4jJlH7SsElV4cOvd
# pnCng+XoxtZnNhVboQQlpLr7OQ/m4Oc78707RF8onyXTSWJMvHDVhBD74qGuY3KF
# mqWGw4MGqGLqECUnUH//xtfhZPMdixuMDBmY7StqkUUuX5TRRVh7zNdVqS7mE+Gz
# EUedzI2ndTVGJtBUI73cU7wUe8lefIEnXzKfxsycTxUos0nUI2YoKGn89ZWPKS/Y
# 4m35WE3YirmTMjK57B5A6KEGSBk9vqyrGNivEGoqJN+mMN8ZULJJKOtFLzgxVg7m
# z5c/JgsMRPvFwZU96hWcLgrNV5D3fNAnWmiCLCMjiI8N8IQszZvAEpzIMIIGcTCC
# BFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcN
# MjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0
# VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEw
# RA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQe
# dGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKx
# Xf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4G
# kbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEA
# AaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7
# fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0g
# AQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYB
# BQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUA
# bQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOh
# IW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS
# +7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlK
# kVIArzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon
# /VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOi
# PPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/
# fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCII
# YdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0
# cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7a
# KLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQ
# cdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+
# NR4Iuto229Nfj950iEkSoYIC0jCCAjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUARAw2kg/n/0n60D7eGy96WYdDT6aggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOPFCRcwIhgPMjAyMTAyMDMxNTM1NTFaGA8yMDIxMDIwNDE1MzU1MVowdzA9Bgor
# BgEEAYRZCgQBMS8wLTAKAgUA48UJFwIBADAKAgEAAgInBAIB/zAHAgEAAgISNjAK
# AgUA48ZalwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAG7yJyJrcRGYmybV
# DDApDHj3g8QljN/h7I54FKwsnoT1XiGJBMBvdhCItdvWuwCQgLRiPkmj7oxXg4lv
# CrGR2ZYoHTveO69thg3X/pTaT4flLGYwCQ1sgeaWtjWr+mC3wYvBASb0E4i81WlG
# pdYh6eskX+jjxlfpxDNtVBohyFkaMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAErk9Dtjgr38EcAAAAAASswDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgQCkNPmukMqT+C8IknXVvX11yAOXdVr81tfU2tkzsk7owgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCBkJznmSoXCUyxc3HvYjOIqWMdG6L6tTAg3KsLa
# XRvPXzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# K5PQ7Y4K9/BHAAAAAAErMCIEIBx/yKkzbMCyP8dpU3A0LhmwIcNW4W5pVUYkjyrI
# b7RWMA0GCSqGSIb3DQEBCwUABIIBAIxyYnP1FMgw+e9UEkwmoJ5kW39Bngi/yXnK
# FhT6zM1ImEnPAOR2ikvDQLegpAaDSKFy/SMwjZWdxqmoLmRZX5fRJO08znKDd4Vt
# AC1ai/VnZK+ZrnJM1MIWdYTK9kUMcS4tiDXIMDOQQ4ZemECy/iDySCCnqIgJ51fM
# CchBqGOgtMDBqrSz/L9N9hL0R3rdXAoCIYDCP9skBY+i/YhzCgWuQS0fgeR1IM32
# aKaavm5HiQ0l+8NRmFrE2n1iZlRqoJys4vzrgm+mqXBMwjWzRwcnO7Ob2Iwo6hR9
# GA3CQr06JT2pU65iQykU1HWQRzhb19fpbBwB2vncIQ9w+DrK9qk=
# SIG # End signature block
