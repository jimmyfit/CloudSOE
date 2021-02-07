Set-StrictMode -Version latest
$ErrorActionPreference = 'Stop'

Import-Module $PSScriptRoot/helpers/DscOperations.psm1 -Force
Import-Module $PSScriptRoot/helpers/GuestConfigurationPolicy.psm1 -Force
Import-LocalizedData -BaseDirectory $PSScriptRoot -FileName GuestConfiguration.psd1 -BindingVariable GuestConfigurationManifest

$currentCulture = [System.Globalization.CultureInfo]::CurrentCulture
if (($currentCulture.Name -eq 'en-US-POSIX') -and ($(Get-OSPlatform) -eq 'Linux')) {
    Write-Warning "'$($currentCulture.Name)' Culture is not supported, changing it to 'en-US'"
    # Set Culture info to en-US
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::new('en-US')
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::new('en-US')
}

#inject version info to GuestConfigPath.psm1
InitReleaseVersionInfo $GuestConfigurationManifest.moduleVersion

<#
    .SYNOPSIS
        Creates a Guest Configuration policy package.

    .Parameter Name
        Guest Configuration package name.

    .Parameter Configuration
        Compiled DSC configuration document full path.

    .Parameter Path
        Output folder path.
        This is an optional parameter. If not specified, the package will be created in the current directory.

    .Parameter ChefInspecProfilePath
        Chef profile path, supported only on Linux.

    .Example
        New-GuestConfigurationPackage -Name WindowsTLS -Configuration ./custom_policy/WindowsTLS/localhost.mof -Path ./git/repository/release/policy/WindowsTLS

    .OUTPUTS
        Return name and path of the new Guest Configuration Policy package.
#>

function New-GuestConfigurationPackage {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Configuration,

        [ValidateNotNullOrEmpty()]
        [string] $ChefInspecProfilePath,

        [ValidateNotNullOrEmpty()]
        [string] $FilesToInclude,

        [string] $Path = '.',

        [switch] $Force
    )

    Try {
        $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
        $unzippedPackagePath = New-Item -ItemType Directory -Force -Path (Join-Path (Join-Path $Path $Name) 'unzippedPackage')
        $Configuration = Resolve-Path $Configuration

        if (-not (Test-Path -Path $Configuration -PathType Leaf)) {
            Throw "Invalid mof file path, please specify full file path for dsc configuration in -Configuration parameter."
        }
         
        Write-Verbose "Creating Guest Configuration package in temporary directory '$unzippedPackagePath'"

        # Verify that only supported resources are used in DSC configuration.
        Test-GuestConfigurationMofResourceDependencies -Path $Configuration -Verbose:$verbose

        # Save DSC configuration to the temporary package path.
        Save-GuestConfigurationMofDocument -Name $Name -SourcePath $Configuration -DestinationPath (Join-Path $unzippedPackagePath "$Name.mof") -Verbose:$verbose

        # Copy DSC resources
        Copy-DscResources -MofDocumentPath $Configuration -Destination $unzippedPackagePath -Verbose:$verbose -Force:$Force

        if (-not [string]::IsNullOrEmpty($ChefInspecProfilePath)) {
            # Copy Chef resource and profiles.
            Copy-ChefInspecDependencies -PackagePath $unzippedPackagePath -Configuration $Configuration -ChefInspecProfilePath $ChefInspecProfilePath
        }

        # Copy FilesToInclude
        if (-not [string]::IsNullOrEmpty($FilesToInclude)) {
            $modulePath = Join-Path $unzippedPackagePath 'Modules'
            if (Test-Path $FilesToInclude -PathType Leaf) {
                Copy-Item -Path $FilesToInclude -Destination $modulePath  -Force:$Force
            }
            else {
                $filesToIncludeFolderName = Get-Item $FilesToInclude
                $FilesToIncludePath = Join-Path $modulePath $filesToIncludeFolderName.Name
                Copy-Item -Path $FilesToInclude -Destination $modulePath -Recurse  -Force:$Force
            }
        }
        
        # Create Guest Configuration Package.
        $packagePath = Join-Path $Path $Name
        New-Item -ItemType Directory -Force -Path $packagePath | Out-Null
        $packagePath = Resolve-Path $packagePath
        $packageFilePath = join-path $packagePath "$Name.zip"
        Remove-Item $packageFilePath -Force -ErrorAction SilentlyContinue

        Write-Verbose "Creating Guest Configuration package : $packageFilePath."
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($unzippedPackagePath, $packageFilePath)

        $result = [pscustomobject]@{
            Name = $Name
            Path = $packageFilePath
        }
        return $result
    }
    Finally {
    }
}

<#
    .SYNOPSIS
        Tests a Guest Configuration policy package.

    .Parameter Path
        Full path of the zipped Guest Configuration package.

    .Parameter Parameter
        Policy parameters.

    .Example
        Test-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip

        $Parameter = @(
            @{
                ResourceType = "Service"            # dsc configuration resource type (mandatory)
                ResourceId = 'windowsService'       # dsc configuration resource property id (mandatory)
                ResourcePropertyName = "Name"       # dsc configuration resource property name (mandatory)
                ResourcePropertyValue = 'winrm'     # dsc configuration resource property value (mandatory)
            })

        Test-GuestConfigurationPackage -Path ./custom_policy/AuditWindowsService.zip -Parameter $Parameter

    .OUTPUTS
        Returns compliance details.
#>

function Test-GuestConfigurationPackage {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [parameter(Mandatory = $false)]
        [Hashtable[]] $Parameter = @()
    )

    if ($env:OS -notmatch "Windows" -and $IsMacOS) {
        Throw 'The Test-GuestConfigurationPackage cmdlet is not supported on MacOS'
    }
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        Throw 'Invalid Guest Configuration package path : $($Path)'
    }

    $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
    $systemPSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Process")

    Try {
        # Create policy folder
        $Path = Resolve-Path $Path
        $policyPath = Join-Path $(Get-GuestConfigPolicyPath) ([System.IO.Path]::GetFileNameWithoutExtension($Path))
        Remove-Item $policyPath -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $policyPath | Out-Null

        # Unzip policy package.
        Expand-Archive -LiteralPath $Path $policyPath

        # Get policy name
        $dscDocument = Get-ChildItem -Path $policyPath -Filter *.mof
        if (-not $dscDocument) {
            Throw "Invalid policy package, failed to find dsc document in policy package."
        }
        $policyName = [System.IO.Path]::GetFileNameWithoutExtension($dscDocument)

        # update configuration parameters
        if ($Parameter.Count -gt 0) {
            Update-MofDocumentParameters -Path $dscDocument.FullName -Parameter $Parameter
        }

        # Unzip Guest Configuration binaries
        $gcBinPath = Get-GuestConfigBinaryPath
        $gcBinRootPath = Get-GuestConfigBinaryRootPath
        if (-not (Test-Path $gcBinPath)) {
            # Clean the bin folder
            Remove-Item $gcBinRootPath'\*' -Recurse -Force -ErrorAction SilentlyContinue

            $zippedBinaryPath = Join-Path $(Get-GuestConfigurationModulePath) 'bin'
            if ($(Get-OSPlatform) -eq 'Windows') {
                $zippedBinaryPath = Join-Path $zippedBinaryPath 'DSC_Windows.zip'
            }
            else {
                # Linux zip package contains an additional DSC folder
                # Remove DSC folder from binary path to avoid two nested DSC folders.
                New-Item -ItemType Directory -Force -Path $gcBinPath | Out-Null
                $gcBinPath = (Get-Item $gcBinPath).Parent.FullName
                $zippedBinaryPath = Join-Path $zippedBinaryPath 'DSC_Linux.zip'
            }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zippedBinaryPath, $gcBinPath)
        }

        # Publish policy package
        Publish-DscConfiguration -ConfigurationName $policyName -Path $policyPath -Verbose:$verbose

        # Set LCM settings to force load powershell module.
        $metaConfigPath = Join-Path $policyPath "$policyName.metaconfig.json"
        "{""debugMode"":""ForceModuleImport""}" | Out-File $metaConfigPath -Encoding ascii
        Set-DscLocalConfigurationManager -ConfigurationName $policyName -Path $policyPath -Verbose:$verbose

        # Clear Inspec profiles
        Remove-Item $(Get-InspecProfilePath) -Recurse -Force -ErrorAction SilentlyContinue

        $testResult = Test-DscConfiguration -ConfigurationName $policyName -Verbose:$verbose
        $getResult = @()
        $getResult = $getResult + (Get-DscConfiguration -ConfigurationName $policyName -Verbose:$verbose)

        $testResult.resources_not_in_desired_state | ForEach-Object {
            $resourceId = $_;
            if ($getResult.count -gt 1) {
                for ($i = 0; $i -lt $getResult.Count; $i++) {
                    if ($getResult[$i].ResourceId -ieq $resourceId) {
                        $getResult[$i] = $getResult[$i] | Select-Object *, @{n = 'complianceStatus'; e = { $false } }
                    }
                }
            }
            elseif ($getResult.ResourceId -ieq $resourceId) {
                $getResult = $getResult | Select-Object *, @{n = 'complianceStatus'; e = { $false } }
            }
        }

        $testResult.resources_in_desired_state | ForEach-Object {
            $resourceId = $_;
            if ($getResult.count -gt 1) {
                for ($i = 0; $i -lt $getResult.Count; $i++) {
                    if ($getResult[$i].ResourceId -ieq $resourceId) {
                        $getResult[$i] = $getResult[$i] | Select-Object *, @{n = 'complianceStatus'; e = { $true } }
                    }
                }
            }
            elseif ($getResult.ResourceId -ieq $resourceId) {
                $getResult = $getResult | Select-Object *, @{n = 'complianceStatus'; e = { $true } }
            }
        }

        $result = New-Object -TypeName PSObject
        $properties = [ordered]@{ complianceStatus = $testResult.compliance_state; resources = $getResult }
        $result | Add-Member -NotePropertyMembers $properties

        return $result;
    }
    Finally {
        $env:PSModulePath = $systemPSModulePath
    }
}

<#
    .SYNOPSIS
        Signs a Guest Configuration policy package using certificate on Windows and Gpg keys on Linux.

    .Parameter Path
        Full path of the Guest Configuration package.

    .Parameter Certificate
        'Code Signing' certificate to sign the package. This is only supported on Windows.

    .Parameter PrivateGpgKeyPath
        Private Gpg key path. This is only supported on Linux.

    .Parameter PublicGpgKeyPath
        Public Gpg key path. This is only supported on Linux.

    .Example
        $Cert = Get-ChildItem -Path Cert:/CurrentUser/AuthRoot -Recurse | Where-Object {($_.Thumbprint -eq "0563b8630d62d75abbc8ab1e4bdfb5a899b65d43") }
        Protect-GuestConfigurationPackage -Path ./custom_policy/WindowsTLS.zip -Certificate $Cert

    .OUTPUTS
        Return name and path of the signed Guest Configuration Policy package.
#>

function Protect-GuestConfigurationPackage {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Certificate")]
        [parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [parameter(Mandatory = $true, ParameterSetName = "Certificate")]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [parameter(Mandatory = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string] $PrivateGpgKeyPath,

        [parameter(Mandatory = $true, ParameterSetName = "GpgKeys")]
        [ValidateNotNullOrEmpty()]
        [string] $PublicGpgKeyPath
    )

    $Path = Resolve-Path $Path
    if (-not (Test-Path $Path -PathType Leaf)) {
        Throw 'Invalid Guest Configuration package path.'
    }

    Try {
        $packageFileName = ([System.IO.Path]::GetFileNameWithoutExtension($Path))
        $signedPackageFilePath = Join-Path (Get-ChildItem $Path).Directory "$($packageFileName)_signed.zip"
        $tempDir = Join-Path (Get-ChildItem $Path).Directory 'temp'
        Remove-Item $signedPackageFilePath -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

        # Unzip policy package.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $tempDir)

        # Get policy name
        $dscDocument = Get-ChildItem -Path $tempDir -Filter *.mof
        if (-not $dscDocument) {
            Throw "Invalid policy package, failed to find dsc document in policy package."
        }
        $policyName = [System.IO.Path]::GetFileNameWithoutExtension($dscDocument)

        $osPlatform = Get-OSPlatform
        if ($PSCmdlet.ParameterSetName -eq "Certificate") {
            if ($osPlatform -eq "Linux") {
                throw 'Certificate signing not supported on Linux.'
            }

            # Create catalog file
            $catalogFilePath = Join-Path $tempDir "$policyName.cat"
            Remove-Item $catalogFilePath -Force -ErrorAction SilentlyContinue
            Write-Verbose "Creating catalog file : $catalogFilePath."
            New-FileCatalog -Path $tempDir -CatalogVersion 2.0 -CatalogFilePath $catalogFilePath | Out-Null

            # Sign catalog file
            Write-Verbose "Signing catalog file : $catalogFilePath."
            $CodeSignOutput = Set-AuthenticodeSignature -Certificate $Certificate -FilePath $catalogFilePath

            $Signature = Get-AuthenticodeSignature $catalogFilePath
            if ($null -ne $Signature.SignerCertificate) {
                if ($Signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint) {
                    throw $CodeSignOutput.StatusMessage
                }
            }
            else { throw $CodeSignOutput.StatusMessage }
        }
        else {
            if ($osPlatform -eq "Windows") {
                throw 'Gpg signing not supported on Windows.'
            }

            $PrivateGpgKeyPath = Resolve-Path $PrivateGpgKeyPath
            $PublicGpgKeyPath = Resolve-Path $PublicGpgKeyPath
            $ascFilePath = Join-Path $tempDir "$policyName.asc"
            $hashFilePath = Join-Path $tempDir "$policyName.sha256sums"

            Remove-Item $ascFilePath -Force -ErrorAction SilentlyContinue
            Remove-Item $hashFilePath -Force -ErrorAction SilentlyContinue

            Write-Verbose "Creating file hash : $hashFilePath."
            pushd $tempDir
            bash -c "find ./ -type f -print0 | xargs -0 sha256sum | grep -v sha256sums > $hashFilePath"
            popd

            Write-Verbose "Signing file hash : $hashFilePath."
            gpg --import $PrivateGpgKeyPath
            gpg --no-default-keyring --keyring $PublicGpgKeyPath --output $ascFilePath --armor --detach-sign $hashFilePath
        }

        # Zip the signed Guest Configuration package
        Write-Verbose "Creating signed Guest Configuration package : $signedPackageFilePath."
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $signedPackageFilePath)

        $result = [pscustomobject]@{
            Name = $policyName
            Path = $signedPackageFilePath
        }
        return $result
    }
    Finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

<#
    .SYNOPSIS
        Publish a Guest Configuration policy package to Azure blob storage.
        The goal is to simplify the number of steps by scoping to a specific
        task.

        Generates a SAS token with a 3-year lifespan, to mitigate the risk
        of a malicious person discovering the published content.

        Requires a resource group, storage account, and container
        to be pre-staged. For details on how to pre-stage these things see the 
        documentation for the Az Storage cmdlets.
        https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-powershell.

    .Parameter Path
        Location of the .zip file containing the Guest Configuration artifacts

    .Parameter ResourceGroupName
        The Azure resource group for the storage account

    .Parameter StorageAccountName
        The name of the storage account for where the package will be published
        Storage account names must be globally unique

    .Parameter StorageContainerName
        Name of the storage container in Azure Storage account (default: "guestconfiguration")

    .Example
        Publish-GuestConfigurationPackage -Path ./package.zip -ResourceGroupName 'resourcegroup' -StorageAccountName 'sa12345'

    .OUTPUTS
        Return a publicly accessible URI containing a SAS token with a 3-year expiration.
#>

function Publish-GuestConfigurationPackage {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName,

        [parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $StorageAccountName,

        [string] $StorageContainerName = 'guestconfiguration',
        
        [switch] $Force
    )

    # Get Storage Context
    $Context = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName | `
        ForEach-Object { $_.Context }

    # Blob name from file name
    $BlobName = Get-Item $Path | ForEach-Object { $_.Name }

    # Upload file
    if ($true -eq $Force) {
        $Blob = Set-AzStorageBlobContent -Context $Context `
            -Container $StorageContainerName `
            -Blob $BlobName `
            -File $Path `
            -Force
    }
    else {
        $Blob = Set-AzStorageBlobContent -Context $Context `
            -Container $StorageContainerName `
            -Blob $BlobName `
            -File $Path
    }

    # Get url with SAS token
    # THREE YEAR EXPIRATION
    $StartTime = Get-Date
    $SAS = New-AzStorageBlobSASToken -Context $Context `
        -Container $StorageContainerName `
        -Blob $BlobName `
        -StartTime $StartTime `
        -ExpiryTime $StartTime.AddYears('3') `
        -Permission 'rl' `
        -FullUri

    # Create object to use property names
    $ContentUri = New-Object -TypeName PSObject -Property @{
        ContentUri = $SAS
    }

    # Output
    return $ContentUri
}

<#
    .SYNOPSIS
        Creates Audit, DeployIfNotExists and Initiative policy definitions on specified Destination Path.

    .Parameter ContentUri
        Public http uri of Guest Configuration content package.

    .Parameter DisplayName
        Policy display name.

    .Parameter Description
        Policy description.

    .Parameter Parameter
        Policy parameters.

    .Parameter Version
        Policy version.

    .Parameter Path
        Destination path.

    .Parameter Platform
        Target platform (Windows/Linux) for Guest Configuration policy and content package.
        Windows is the default platform.

    .Parameter Tag
        The name and value of a tag used in Azure.

    .Example
        New-GuestConfigurationPolicy `
                                 -ContentUri https://github.com/azure/auditservice/release/AuditService.zip `
                                 -DisplayName 'Monitor Windows Service Policy.' `
                                 -Description 'Policy to monitor service on Windows machine.' `
                                 -Version 1.0.0.0 
                                 -Path ./git/custom_policy
                                 -Tag @{Owner = 'WebTeam'}

        $PolicyParameterInfo = @(
            @{
                Name = 'ServiceName'                                       # Policy parameter name (mandatory)
                DisplayName = 'windows service name.'                      # Policy parameter display name (mandatory)
                Description = "Name of the windows service to be audited." # Policy parameter description (optional)
                ResourceType = "Service"                                   # dsc configuration resource type (mandatory)
                ResourceId = 'windowsService'                              # dsc configuration resource property name (mandatory)
                ResourcePropertyName = "Name"                              # dsc configuration resource property name (mandatory)
                DefaultValue = 'winrm'                                     # Policy parameter default value (optional)
                AllowedValues = @('wscsvc','WSearch','wcncsvc','winrm')    # Policy parameter allowed values (optional)
            })

            New-GuestConfigurationPolicy -ContentUri 'https://github.com/azure/auditservice/release/AuditService.zip' `
                                 -DisplayName 'Monitor Windows Service Policy.' `
                                 -Description 'Policy to monitor service on Windows machine.' `
                                 -Version 1.0.0.0 
                                 -Path ./policyDefinitions `
                                 -Parameter $PolicyParameterInfo 

    .OUTPUTS
        Return name and path of the Guest Configuration policy definitions.
#>

function New-GuestConfigurationPolicy {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ContentUri,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DisplayName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Description,

        [parameter()]
        [Hashtable[]] $Parameter,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [version] $Version = '1.0.0',

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter()]
        [ValidateSet('Windows', 'Linux')]
        [string]
        $Platform = 'Windows',

        [parameter()]
        [Hashtable[]] $Tag
    )

    # This value must be static for AINE policies due to service configuration
    $Category = 'Guest Configuration'

    Try {
        $verbose = ($PSBoundParameters.ContainsKey("Verbose") -and ($PSBoundParameters["Verbose"] -eq $true))
        $policyDefinitionsPath = $Path
        $unzippedPkgPath = Join-Path $policyDefinitionsPath 'temp'
        $tempContentPackageFilePath = Join-Path $policyDefinitionsPath 'temp.zip'

        # update parameter info
        $ParameterInfo = Update-PolicyParameter -Parameter $Parameter

        New-Item -ItemType Directory -Force -Path $policyDefinitionsPath | Out-Null

        # Check if ContentUri is a valid web Uri
        $uri = $ContentUri -as [System.URI]
        if (-not ($uri.AbsoluteURI -ne $null -and $uri.Scheme -match '[http|https]')) {
            Throw "Invalid ContentUri : $ContentUri. Please specify a valid http URI in -ContentUri parameter."
        }

        # Generate checksum hash for policy content.
        Invoke-WebRequest -Uri $ContentUri -OutFile $tempContentPackageFilePath
        $tempContentPackageFilePath = Resolve-Path $tempContentPackageFilePath
        $contentHash = (Get-FileHash $tempContentPackageFilePath -Algorithm SHA256).Hash
        Write-Verbose "SHA256 Hash for content '$ContentUri' : $contentHash."

        # Get the policy name from policy content.
        Remove-Item $unzippedPkgPath -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $unzippedPkgPath | Out-Null
        $unzippedPkgPath = Resolve-Path $unzippedPkgPath
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempContentPackageFilePath, $unzippedPkgPath)
        $dscDocument = Get-ChildItem -Path $unzippedPkgPath -Filter *.mof -Exclude '*.schema.mof' -Depth 1
        if (-not $dscDocument) {
            Throw "Invalid policy package, failed to find dsc document in policy package."
        }
        $policyName = [System.IO.Path]::GetFileNameWithoutExtension($dscDocument)

        $packageIsSigned = (((Get-ChildItem -Path $unzippedPkgPath -Filter *.cat) -ne $null) -or `
            (((Get-ChildItem -Path $unzippedPkgPath -Filter *.asc) -ne $null) -and ((Get-ChildItem -Path $unzippedPkgPath -Filter *.sha256sums) -ne $null)))

        $AuditIfNotExistsInfo = @{
            FileName                 = 'AuditIfNotExists.json'
            DisplayName              = $DisplayName
            Description              = $Description
            Platform                 = $Platform
            ConfigurationName        = $policyName
            ConfigurationVersion     = $Version
            ContentUri               = $ContentUri
            ContentHash              = $contentHash
            ReferenceId              = "Deploy_$policyName"
            ParameterInfo            = $ParameterInfo
            UseCertificateValidation = $packageIsSigned
            Category                 = $Category
            Tag                      = $Tag
        }
        New-CustomGuestConfigPolicy -PolicyFolderPath $policyDefinitionsPath -AuditIfNotExistsInfo $AuditIfNotExistsInfo -Verbose:$verbose | Out-Null
            
        $result = [pscustomobject]@{
            Name = $policyName
            Path = $Path
        }
        return $result
    }
    Finally {
        # Remove temporary content package.
        Remove-Item $tempContentPackageFilePath -Force -ErrorAction SilentlyContinue
        Remove-Item $unzippedPkgPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

<#
    .SYNOPSIS
        Publishes the Guest Configuration policy in Azure Policy Center.

    .Parameter Path
        Guest Configuration policy path.

    .Example
        Publish-GuestConfigurationPolicy -Path ./git/custom_policy
#>

function Publish-GuestConfigurationPolicy {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [parameter(Mandatory = $false)]
        [string] $ManagementGroupName
    )

    $rmContext = Get-AzContext
    Write-Verbose "Publishing Guest Configuration policy using '$($rmContext.Name)' AzContext."

    # Publish policies
    $subscriptionId = $rmContext.Subscription.Id
    $policyFile = join-path $Path "AuditIfNotExists.json"
    $jsonDefinition = Get-Content $policyFile | ConvertFrom-Json | ForEach-Object { $_ }
    $definitionContent = $jsonDefinition.Properties

    $newAzureRmPolicyDefinitionParameters = @{
        Name        = $jsonDefinition.name
        DisplayName = $($definitionContent.DisplayName | ConvertTo-Json -Depth 20).replace('"', '')
        Description = $($definitionContent.Description | ConvertTo-Json -Depth 20).replace('"', '')
        Policy      = $($definitionContent.policyRule | ConvertTo-Json -Depth 20)
        Metadata    = $($definitionContent.Metadata | ConvertTo-Json -Depth 20)
        ApiVersion  = '2018-05-01'
        Verbose     = $true
    }

    if ($definitionContent.PSObject.Properties.Name -contains 'parameters') {
        $newAzureRmPolicyDefinitionParameters['Parameter'] = ConvertTo-Json -InputObject $definitionContent.parameters -Depth 15
    }

    if ($ManagementGroupName) {
        $newAzureRmPolicyDefinitionParameters['ManagementGroupName'] = $ManagementGroupName
    }

    Write-Verbose "Publishing '$($jsonDefinition.properties.displayName)' ..."
    New-AzPolicyDefinition @newAzureRmPolicyDefinitionParameters
}

Export-ModuleMember -Function @('New-GuestConfigurationPackage', 'Test-GuestConfigurationPackage', 'Protect-GuestConfigurationPackage', 'Publish-GuestConfigurationPackage', 'New-GuestConfigurationPolicy', 'Publish-GuestConfigurationPolicy')

# SIG # Begin signature block
# MIIjjwYJKoZIhvcNAQcCoIIjgDCCI3wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCATk0OMbE8MYH52
# L1hyb7nOW7SKHb+xI0oWojsY5x+lc6CCDYEwggX/MIID56ADAgECAhMzAAABh3IX
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVZDCCFWACAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgTM0ZUDQZ
# 0GG510LsgqFHqFJfnry9g20mYIUTGNSwW3cwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQC0M6/g0z0p6qhLb6bi6FS0dzfDRjdnDEDuLvoRJl2G
# 33pb96D96M1Mzt6u7rsH9T9zTJodZir2CAEtCafah3q/DyXuD/74rsRyGMOOXwas
# fowSnCGmQcTS9PNwz+iQhDdprzBts7pbdf4iADIudXC3561C6GdO76GZ4bJsfjWT
# nEjy3P2eBiZCejlHs+9g3A131kZ+/Fq+zZ9VB01sg/N/ILLrpFh5CHnbEKUS9XBU
# gV/+566XpGU6yKvQJN0DhBQyshkwrx/4Tac8GKH/AcxjbOqq7qcP/cLrcbxUKgqd
# pcJKcX0aHVJQ9cTfS0L35N1pdPlx6qfHH8vhEmYYKFVEoYIS7jCCEuoGCisGAQQB
# gjcDAwExghLaMIIS1gYJKoZIhvcNAQcCoIISxzCCEsMCAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIFTsj+fwM56ZzbSLByqmVUO5SwkiaTIJUvYKFa9L
# nW0EAgZgGeLnu6sYEzIwMjEwMjAzMTUxOTM2LjUxNlowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCDkEwggT1MIID3aADAgECAhMzAAABLCKvRZd1+RvuAAAA
# AAEsMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTE5MTIxOTAxMTUwM1oXDTIxMDMxNzAxMTUwM1owgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdB
# LUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPK1zgSSq+MxAYo3qpCt
# QDxSMPPJy6mm/wfEJNjNUnYtLFBwl1BUS5trEk/t41ldxITKehs+ABxYqo4Qxsg3
# Gy1ugKiwHAnYiiekfC+ZhptNFgtnDZIn45zC0AlVr/6UfLtsLcHCh1XElLUHfEC0
# nBuQcM/SpYo9e3l1qY5NdMgDGxCsmCKdiZfYXIu+U0UYIBhdzmSHnB3fxZOBVcr5
# htFHEBBNt/rFJlm/A4yb8oBsp+Uf0p5QwmO/bCcdqB15JpylOhZmWs0sUfJKlK9E
# rAhBwGki2eIRFKsQBdkXS9PWpF1w2gIJRvSkDEaCf+lbGTPdSzHSbfREWOF9wY3i
# Yj8CAwEAAaOCARswggEXMB0GA1UdDgQWBBRRahZSGfrCQhCyIyGH9DkiaW7L0zAf
# BgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0
# YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBPFxHIwi4vAH49w9Svmz6K3tM55RlW
# 5pPeULXdut2Rqy6Ys0+VpZsbuaEoxs6Z1C3hMbkiqZFxxyltxJpuHTyGTg61zfNI
# F5n6RsYF3s7IElDXNfZznF1/2iWc6uRPZK8rxxUJ/7emYXZCYwuUY0XjsCpP9pbR
# RKeJi6r5arSyI+NfKxvgoM21JNt1BcdlXuAecdd/k8UjxCscffanoK2n6LFw1PcZ
# lEO7NId7o+soM2C0QY5BYdghpn7uqopB6ixyFIIkDXFub+1E7GmAEwfU6VwEHL7y
# 9rNE8bd+JrQs+yAtkkHy9FmXg/PsGq1daVzX1So7CJ6nyphpuHSN3VfTMIIGcTCC
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
# NR4Iuto229Nfj950iEkSoYICzzCCAjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUADE5OKSMoNx/mYxYWap1RTOohbJ2ggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOPFChkwIhgPMjAyMTAyMDMxNTQwMDlaGA8yMDIxMDIwNDE1NDAwOVowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA48UKGQIBADAHAgEAAgIXmDAHAgEAAgIRyTAKAgUA
# 48ZbmQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAHeeznL2n6HWCjHH94Fl
# hcdW6TEXzq4XNgp1Gx1W9F8gJ4x+SwoV7elJZkwgGffcpHomLvIY/VSuzsl1NgtJ
# TWM2UxoqSv58BBOrl4eGhH6kkg8Ucy2tdeK5T8cHa8pMkq2j9pFd2mRG/6VMk0dl
# Xz7Uy3Z6bZqkcABMyAfuAaGbMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAEsIq9Fl3X5G+4AAAAAASwwDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgx71qe5y2QGv9FjsvAgryLh5Buv8vhauGjtKnQBm5AHwwgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBbn/0uFFh42hTM5XOoKdXevBaiSxmYK9Ilcn9nu5ZH
# 4TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABLCKv
# RZd1+RvuAAAAAAEsMCIEIIfIM3YbzHswb/Kj/qq1l1cHA6QBl+gEXYanUNJomrpT
# MA0GCSqGSIb3DQEBCwUABIIBAEmKphuNmlSUKzIAzkFGjNwhsYUF65JegwwELP1c
# m72M+6shZdJ9XuyWIPJ+W1a6E6ltCSOsaEiQdg7UNLgPxk1D4KysY8ZZwb+OV1Zm
# esFT6N+tGibaudQ6w7SaHk8q6nwW1kHgy2SVeI6dTfUc8ha7muBfe6cJcj82pEQc
# 8Vzjf+3cU8jP3w121p1JJFrYs7UAN+o/K0JS1MelydKc3R/SlIoDlsZ4Gx4YZrbO
# F6JJTxtf2mYnHuAc/1bfUI4zK8+9Wjkayt3sAQq4MDyP6YMDkzzgNYPt4dVjXIfC
# LeLkkez6DPrKAtdnSv+rlzcKhZhXVmyyYMrltq+3Av4iQSE=
# SIG # End signature block
