<#

TSPersistentService

Proof-of-concept script for live analysis of persistent 
Windows Services [MITRE T1543.003] as presented in the 
2021 SEC-T Conference.

Developed by:
  Alexander Andersson (@mranderssona)
  TRUESEC DFIR

Credits and thanks to:
  - Jared Atkinson for the v2-compatible Get-Hash function
  - Boe Prox for the Get-RegistryTimestamp function

Required Dependencies: 
  None

#>

#region Functions
Function Get-RegistryKeyTimestamp {
    <#
    Get the timestamp of a registry key 
    Author: Boe Prox
    Links: https://learn-powershell.net/2014/12/18/retrieving-a-registry-key-lastwritetime-using-powershell/
    #>
    [OutputType('Microsoft.Registry.Timestamp')]
    [cmdletbinding(
        DefaultParameterSetName = 'ByValue'
    )]
    Param (
        [parameter(ValueFromPipeline=$True, ParameterSetName='ByValue')]
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [parameter(ParameterSetName='ByPath')]
        [string]$SubKey,
        [parameter(ParameterSetName='ByPath')]
        [Microsoft.Win32.RegistryHive]$RegistryHive,
        [parameter(ParameterSetName='ByPath')]
        [string]$Computername
    )
    Begin {
        #region Create Win32 API Object
        Try {
            [void][advapi32]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
            #endregion Module Builder
 
            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')
 
            #region RegQueryInfoKey Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                    [System.Text.StringBuilder], #Class Name
                    [UInt32 ].MakeByRefType(),  #Class Length
                    [UInt32], #Reserved
                    [UInt32 ].MakeByRefType(), #Subkey Count
                    [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                    [UInt32 ].MakeByRefType(), #Max Class Length
                    [UInt32 ].MakeByRefType(), #Value Count
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Security Descriptor Size           
                    [long].MakeByRefType() #LastWriteTime
                ) #Method Parameters
            )
 
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(       
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )
 
            $FieldValueArray = [Object[]] @(
                'RegQueryInfoKey', #CASE SENSITIVE!!
                $True
            )
 
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('advapi32.dll'),
                $FieldArray,
                $FieldValueArray
            )
 
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion RegQueryInfoKey Method
 
            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Constant Variables
        $ClassLength = 255
        [long]$TimeStamp = $null
        #endregion Constant Variables
 
        #region Registry Key Data
        If ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            #Get registry key data
            $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computername).OpenSubKey($SubKey)
            If ($RegistryKey -isnot [Microsoft.Win32.RegistryKey]) {
                Throw "Cannot open or locate $SubKey on $Computername"
            }
        }
 
        $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
        $RegistryHandle = $RegistryKey.Handle
        #endregion Registry Key Data
 
        #region Retrieve timestamp
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        )
        Switch ($Return) {
            0 {
               #Convert High/Low date to DateTime Object
                $LastWriteTime = [datetime]::FromFileTime($TimeStamp)
 
                #Return object
                $LastWriteTime
                #$Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                #$Object
            }
            122 {
                Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
            }
            Default {
                Throw "Error ($return) occurred"
            }
        }
        #endregion Retrieve timestamp
    }
}

function Get-FileInfo($fullPath) {
    <# 
    Get forensically useful information about a file.
    The input can be a file, or a command line. In case it is a 
    command line it will get the info for the image path. 
    #>
    try {
        $imagePath = Get-ImagePath "$fullPath"
    } catch  {
        Write-Warning "Error when extracting imagepath from command line `"$fullPath`""
    }
    if($imagePath) { 
        $signature = Get-AuthenticodeSignature -FilePath $imagePath -ErrorAction SilentlyContinue
        if($signature) {
            $signed = switch ($signature.Status) {
                'Valid' {
                    $true
                    break
                }
                'NotSigned' {
                    $false
                    break
                }
                default {
                    $false
                }
            }
            $IsSigned = $signed
            $IsOSBinary = $signature.IsOSBinary
            $SignatureSubject = $signature.SignerCertificate.Subject
            $SignatureIssuer = $signature.SignerCertificate.IssuerName.Name
        } else {
            $IsSigned = "Error"
            $IsOSBinary = "Error"
            $SignatureSubject = "Error"
            $SignatureIssuer = "Error"
        }

        $i = get-item -LiteralPath "$imagePath" -ErrorAction SilentlyContinue
        $attributes = [PSCustomObject]@{ 
            FullName = $i."FullName"            
            CreationTimeUtc = ($i."CreationTimeUtc").ToString("yyyy-MM-dd HH:mm:ss")
            LastWriteTimeUtc = ($i."LastWriteTimeUtc").ToString("yyyy-MM-dd HH:mm:ss")
            LastAccessTimeUtc = ($i."LastAccessTimeUtc").ToString("yyyy-MM-dd HH:mm:ss")
            Owner = (Get-Acl -Path "$imagePath" ).Owner
            Mode = $i."Mode"
            MD5 = (Get-Hash -FilePath "$imagePath" -Algorithm MD5).Hash
            SHA1 = (Get-Hash -FilePath "$imagePath" -Algorithm SHA1).Hash
            LinkType = $i."LinkType"
            Length = $i."Length"
            FileDescription = ($i."VersionInfo")."FileDescription"
            ProductName = ($i."VersionInfo")."ProductName"
            IsSigned = $signed
            IsOSBinary = $signature.IsOSBinary
            SignatureSubject = $signature.SignerCertificate.Subject
            SignatureIssuer = $signature.SignerCertificate.IssuerName.Name
        }
    }
    else {
        Write-Warning "Failed to extract imagepath from command line `"$fullPath`""
        $attributes = $null
    }

    $attributes
}

function Get-ImagePath($string) {
    <#
    Extract the image path from a command line.  
    E.g. if command line is 
        C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted
    then we want it to return 
        C:\WINDOWS\system32\svchost.exe
    
    This function handles most, but not all cases. 
    Disclaimer: This script is a PoC, there will be LoTR-style dragons in this function :-) 
    #>
    $result = $null
    $string = $string.ToLower()
    if( $string -like 'hklm:*' -or $string -like 'hkcc:*' -or $string -like 'hkcr:*' -or $string -like 'hku:*' -or $string -like "{*") {
        $result = $null 
    } else {
        # Fix relative drivers references 
        if( $string -like "\SystemRoot\System32\drivers\*.sys") {
            $expanded = "$env:SystemRoot\System32\drivers\"
            $string = $string.Replace("\systemroot\system32\drivers\",$expanded)
        }
        if( $string -like "System32\drivers\*.sys") { 
            $expanded = "$env:SystemRoot\System32\drivers\"
            $string = $string.Replace("system32\drivers\",$expanded)
        }
        if( $string -like "\SystemRoot\System32\DriverStore\*.sys") { 
            $expanded = "$env:SystemRoot\System32\DriverStore\"
            $string = $string.Replace("\systemroot\system32\driverstore\",$expanded)
        }
        # Path prefixes and legacy paths
        if( $string -like "\??\UNC\*") {
            $string = $string.Replace("\??\UNC\","\\")
        }
        if( $string -like "\??\*") {
            $string = $string.Replace("\??\","")
        }
        if( $string -like "\\?\*") {
            $string = $string.Replace("\?\","")
        }
        if( $string -like "\\.\*") {
            $string = $string.Replace("\\.\","")
        }
        if( $string -like "\Global??\C:*") {
            $string = $string.Replace("\Global??\C:","C:")
        }
        if( $string -like "\\127.0.0.1\c$*") {
            $string = $string.Replace("\\127.0.0.1\","C:")
        }
        if( $string -like "127.0.0.1\c$*") {
            $string = $string.Replace("127.0.0.1\c$","C:")
        }
        if( $string -like "\\LOCALHOST\c$*") {
            $string = $string.Replace("\\LOCALHOST\c$","C:")
        }
        if( $string -like "LOCALHOST\c$*") {
            $string = $string.Replace("LOCALHOST\c$","C:")
        }
        # Resolve CMD variables 
        $command = [System.Environment]::ExpandEnvironmentVariables($command)

        # Remove irrelevant characters
        $string = $string.Replace('"','')
        $string = $string.Replace('*','')
        $string = $string.Replace('>','')
        $string = $string.Replace('<','')
        $string = $string.Replace('?','')
    
        if($string.Length -le 1) {
            $result = $null
        }
        elseif( $string -like "\\*" ) {
            # Never look up UNC paths
            $result = $null
        }
        else {
            try {
                # Guess your way to the right number of whitepaces
                $spaces = ($string -Split ' ')
                for($x = 0; $x -lt $spaces.length; $x++){
                    $string = $spaces[0]
                    for($y = 1; $y -lt $x+1; $y++){
                        $string = "$string $($spaces[$y])"
                    }
                    $isCommand = get-command "$string" -ErrorAction SilentlyContinue
                    if($isCommand) {
                        $string = $isCommand.Definition 
                    }
                    $isFile = Get-Item "$string" -ErrorAction SilentlyContinue
                    if($isFile -and !($isFile.PsIsContainer)) {
                        $result = $string 
                        break
                    }
                }
            } catch { $result = $null }
        }
    }
    "$result"
}

function Get-Hash {
    <#
    PowerShell v2 port of the Get-FileHash function. This version of Get-Hash supports hashing files and strings. 
    
    Link: https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}

Add-Type  @"
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig = 1,
      ChangeConfig = 2,
      QueryStatus = 4,
      EnumerateDependents = 8,
      Start = 16,
      Stop = 32,
      PauseContinue = 64,
      Interrogate = 128,
      UserDefinedControl = 256,
      Delete = 65536,
      ReadControl = 131072,
      WriteDac = 262144,
      WriteOwner = 524288,
      Synchronize = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll = 268435456,
      GenericExecute = 536870912,
      GenericWrite = 1073741824,
      GenericRead = 2147483648
  }
"@
function Get-ServiceAcl($key) {
    <#
    Get the ACL of a service
    #>
    $security = Get-ItemProperty -Path "$key\Security" -ErrorAction SilentlyContinue
    if(!($security -and $security.Security)) {
        return 
    } else {
        $Sddl = $security.Security 
        try {
            $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl, 0)
        }
        catch {
            Write-Warning "Failed to get security descriptor for service '$key': $Sddl"
            return
        }
        $result = New-Object -TypeName PSObject -Property (@{
            ControlFlags = $Dacl.ControlFlags
            Owner = $Dacl.Owner.Value
            Group = $Dacl.Group.Value
            ResourceManagerControl = $Dacl.ResourceManagerControl
        })
        $access = @()
        $Dacl.DiscretionaryAcl | ForEach-Object {
            $CurrentDacl = $_
            try {
                $IdentityReference = $CurrentDacl.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
            }
            catch {
                $IdentityReference = $CurrentDacl.SecurityIdentifier
            }
            $access += (New-Object -TypeName PSObject -Property (@{ 
                AccessControlType = $CurrentDacl.AceType | % { "{0}" -f $_ }
                IdentityReference = $IdentityReference.Value
                ServiceRights = [ServiceAccessFlags] $CurrentDacl.AccessMask | % { "{0}" -f $_ }
            }))
        }
        $null = $result | Add-Member -MemberType NoteProperty -Name Access -Value $access 
 
        $result
    }
}
#endregion Functions

#region Main
function Get-TSPersistentService {
    <#
    Get detailed information about services 
    #>
    [CmdletBinding()]
    $ServiceStartModeEnum = [pscustomobject]@{
        0="Boot"
        1="System"
        2="Auto"
        3="Manual"
        4="Disabled"
    }
    $ServiceTypeEnum = [pscustomobject]@{
        0="Unknown"
        1="KernelDriver"
        2="FileSystemDriver"
        4="Adapter"
        8="RecognizerDriver"
        16="Win32OwnProcess"
        32="Win32ShareProcess"
        256="InteractiveProcess"
    }
    $ServiceProtectedEnum = [pscustomobject]@{
        0="NONE"
        1="WINDOWS"
        2="WINDOWS_LIGHT"
        3="ANTIMALWARE_LIGHT"
    }
    (Get-Item -Path 'HKLM:\System\CurrentControlSet\Services').GetSubKeyNames() | ForEach-Object {
        $ServiceName = $_ 
        $key  = "HKLM:\System\CurrentControlSet\Services\$ServiceName"

        # Get service type
        try {
            $Type = Get-ItemProperty -Path $key -Name Type -ErrorAction Stop
        } catch {
            $Type = 0
        }        
        $category = $ServiceTypeEnum."$($Type.Type)"
        
        # Get regkey timestamp 
        try {
            $reglastwrite = (Get-Item "$key" | Get-RegistryKeyTimestamp).ToString("yyyy-MM-dd HH:mm:ss")
        }
        catch {
            $reglastwrite = "ERROR"
        }

        # Get service imagepath 
        $imagepath = Get-ItemProperty -Path "$key" -Name ImagePath -ErrorAction SilentlyContinue
        if($imagepath) {
            $imgpath = $imagepath.ImagePath
            $imgpathinfo = Get-FileInfo "$imgpath"
        } 
        else {
            $imgpath = $null
            $imgpathinfo = $null
        }
        
        # Get dependencies
        $dependonservice = Get-ItemProperty -Path "$key" -Name DependOnService -ErrorAction SilentlyContinue
        if($dependonservice) { $dependonserviceval = $dependonservice.DependOnService  }
        else {$dependonserviceval = @() }
        
        # Get required privileges
        $requiredprivs = Get-ItemProperty -Path "$key" -Name RequiredPrivileges -ErrorAction SilentlyContinue 
        if($requiredprivs) { $requiredprivileges = $requiredprivs.RequiredPrivileges  }
        else {$requiredprivileges = @() }
        
        # Get ACL
        $serviceacl = Get-ServiceAcl -key "$key"
        if($serviceacl) {
            $serviceowner = $serviceacl.Owner 
            $servicecontrolflags = $serviceacl.ControlFlags
            $serviceaccess = $serviceacl.Access
        } else {
            $serviceowner = "?"
            $servicecontrolflags = ""
            $serviceaccess = @()
        }
        
        # Get service dll 
        $servicedll = Get-ItemProperty -Path "$key/Parameters" -Name ServiceDll -ErrorAction SilentlyContinue
        if($servicedll) {
            $serviceDllPath = $servicedll.ServiceDll
            $serviceDllDetails = Get-FileInfo "$serviceDllPath"
        } 
        else {
            $serviceDllPath = $null
            $serviceDllDetails = $null
        }

        # Check if it is a protected service
        $protected = Get-ItemProperty -Path "$key" -Name LaunchProtected -ErrorAction SilentlyContinue
        if($protected -and $protected.LaunchProtected) {
            $protected = $protected.LaunchProtected
        } else {
            $protected = 0
        } 
        
        # Get start mode
        $start = Get-ItemProperty -Path "$key" -Name Start -ErrorAction SilentlyContinue
        if($start) { $startMode = $ServiceStartModeEnum."$($start.start)" }
        else {$startMode = '?'}
        
        # Get start user
        $objectname = Get-ItemProperty -Path "$key" -Name ObjectName -ErrorAction SilentlyContinue
        if($objectname) { $startUser = $objectname.objectname }
        else {$startUser = '?' }
        
        # Print results as an object
        [pscustomobject]@{
            Name = $ServiceName
            Category = $category
            RegPath = $key
            RegLastWriteTimeUTC = $reglastwrite
            StartMode = $startMode
            StartUser = $startUser
            Protected = $ServiceProtectedEnum."$protected"
            Owner = $serviceowner
            Access = $serviceaccess
            ControlFlags = $servicecontrolflags | % { "{0}" -f $_ }
            DependOnService = $dependonserviceval
            RequiredPrivileges = $requiredprivileges
            CommandLine = $imgpath
            CommandLineDetails = $imgpathinfo
            ServiceDLLPath = $serviceDllPath
            ServiceDLLDetails = $serviceDllDetails
        } 
    }
}

function ConvertTo-TSTimeline {
    <#
    Convert the result of Get-TSPersistentService to a timeline
    #>
    [CmdletBinding()]
    param(
        [Parameter( Mandatory=$true, ValueFromPipeline=$true )]
        [pscustomobject]$Services
        )
    Begin
    {
        $timeline = New-Object -TypeName "System.Collections.ArrayList"
    }
    Process
    {
        if($_.ServiceDLLDetails) {
            $servicedllmd5 = "$($_.ServiceDLLDetails.MD5)"
        }  else {
            $servicedllmd5 = $null
        }
        if($_.CommandLineDetails) {
            $imagemd5 = $_.CommandLineDetails.MD5
        } else {
            $servicedllmd5 = $null
        }   
        if($_.ServiceDLLDetails) {
            # Create row for service dll last write time
            $timeline.Add([pscustomobject]@{
                Timestamp = $_.ServiceDLLDetails.LastWriteTimeUTC
                Event = "Servicedll last write" 
                Name = $_.Name
                Category = $_.Category
                StartMode = $_.StartMode
                CommandLine = $_.CommandLine
                ImagePathMD5 = $imagemd5
                ServiceDLL = $_.ServiceDLLPath
                ServiceDLLMD5 = $servicedllmd5
            }) | out-null
            # Create row for service dll creation time
            $timeline.Add([pscustomobject]@{
                Timestamp = $_.ServiceDLLDetails.CreationTimeUTC
                Event = "Servicedll creation" 
                Name = $_.Name
                Category = $_.Category
                StartMode = $_.StartMode
                CommandLine = $_.CommandLine
                ImagePathMD5 = $imagemd5
                ServiceDLL = $_.ServiceDLLPath
                ServiceDLLMD5 = $servicedllmd5
            }) | out-null
        } 
        if($_.CommandLineDetails) {
            # Create row for image path last write time
            $timeline.Add([pscustomobject]@{
                Timestamp = $_.CommandLineDetails.LastWriteTimeUTC
                Event = "Service imagepath last write"
                Name = $_.Name
                Category = $_.Category
                StartMode = $_.StartMode
                CommandLine = $_.CommandLine
                ImagePathMD5 = $imagemd5
                ServiceDLL = $_.ServiceDLLPath
                ServiceDLLMD5 = $servicedllmd5
            }) | out-null
            # Create row for image path creation time
            $timeline.Add([pscustomobject]@{
                Timestamp = $_.CommandLineDetails.CreationTimeUTC
                Event = "Service imagepath creation"
                Name = $_.Name
                Category = $_.Category
                StartMode = $_.StartMode
                CommandLine = $_.CommandLine
                ImagePathMD5 = $imagemd5
                ServiceDLL = $_.ServiceDLLPath
                ServiceDLLMD5 = $servicedllmd5
            }) | out-null
        }
        # Create row for registry key last write time
        $timeline.Add([pscustomobject]@{
            Timestamp =  $_.reglastwritetimeutc
            Event = "Service regkey last write" 
            Name = $_.Name
            Category = $_.Category
            StartMode = $_.StartMode
            CommandLine = $_.CommandLine
            ImagePathMD5 = $imagemd5
            ServiceDLL = $_.ServiceDLLPath
            ServiceDLLMD5 = $servicedllmd5
        }) | out-null
    }
    End
    {
        # sort and write results to file
        $timeline | Sort-Object -Property Timestamp 
    }
}
#endregion Main
