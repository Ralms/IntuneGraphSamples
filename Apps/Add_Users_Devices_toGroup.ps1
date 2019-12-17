<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>


Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
    if ($AadModule -eq $null) {
        
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "91dfa2b6-de64-41e2-8bd0-58f34b418cfb"
$clientSecret = "545_Q6hEx@Oz.Ex]kbFMqCOFvUvJFkk2"
$tenant = "5365bc0f-9115-45a1-8a2a-4195fc48ab67"

#$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $clientCredential = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList ($clientId, $clientSecret)

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientCredential).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

###################################

Function Get-AADGroup(){

    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with AAD
    .EXAMPLE
    Get-AADGroup
    Returns all users registered with Azure AD
    .NOTES
    NAME: Get-AADGroup
    #>

    [cmdletbinding()]
    param
    (
        $groupId,
        [switch]$members
    )

    # Defining Variables
    $baseURI = "https://graph.microsoft.com/v1.0/groups"

    try 
    {
        if($groupId)
        {
            $uri = $baseURI + "/$($groupId)?`$select=id,displayName"
            $group = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

            if($members -and $group)
            {
                $memberObjects = Get-AADGroupMembers -id $groupId
                $group | Add-Member -Name 'members' -Type NoteProperty -Value $memberObjects
            }
            return $group
        }
    }
    catch 
    {
        write-host "Get-AADGroup exception"
        $_.Exception

        exit
    }
}

##################################################

Function Get-AADGroupMembers(){

    <#
    .SYNOPSIS
    This function is used to get AAD Groups Members from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all members for a specific group recursively
    .EXAMPLE
    Get-AADGroupMembers
    Returns all members of the group
    .NOTES
    NAME: Get-AADGroupMembers
    #>

    [cmdletbinding()]
    param
    (
        $id
    )

    # Defining Variables
    $baseURI = "https://graph.microsoft.com/v1.0/groups"

    try 
    {
        if($id)
        {
            $uri = $baseURI + "/$($id)/members?`$select=displayName,userPrincipalName,id"
            $membersResp = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

            $membersResult = @()

            # Recursively go over all members, if it's a Group get it's membershipt instead
            foreach($obj in $membersResp){
                if($obj.'@odata.type' -ne "#microsoft.graph.group"){
                    $membersResult += $obj
                }else{
                    $membersResult += Get-AADGroupMembers -id $obj.id
                }
            }

            return $membersResult
        }
    }
    catch 
    {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    }
}


###################################


Function Get-ManagedDevices(){

<#
.SYNOPSIS
This function is used to get Intune Managed Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Intune Managed Device
.EXAMPLE
Get-ManagedDevices
Returns all managed devices but excludes EAS devices registered within the Intune Service
.EXAMPLE
Get-ManagedDevices -IncludeEAS
Returns all managed devices including EAS devices registered within the Intune Service
.NOTES
NAME: Get-ManagedDevices
#>


    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"
    $zeros = "00000000-0000-0000-0000-000000000000"
    $TimeNow = (Get-Date).ToUniversalTime()
    #Puts time back X days
    $TimeOld= (Get-Date).ToUniversalTime().AddDays(-200)
    
    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$select=id,azureADDeviceId,userId,deviceName,enrolledDateTime,deviceRegistrationState"
        $deviceClean = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
 
 
        return $deviceClean | where-Object {
            $_.azureADDeviceId -ne $zeros -and 
            $_.deviceRegistrationState -eq "registered" -and 
            ($_.userId -ne "" -or $_.userId -ne $zeros) -and
            $(Get-Date($_.enrolledDateTime)) -ge $TimeOld  
        }
        

    }
    catch {

    Write-Error "Request to $Uri failed "
    $_.Exception
    write-host
    break

    }

}


################################

Function Get-AADDevice(){

<#
.SYNOPSIS
This function is used to get an AAD Device from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an AAD Device registered with AAD
.EXAMPLE
Get-AADDevice -DeviceID $DeviceID
Returns an AAD Device from Azure AD
.NOTES
NAME: Get-AADDevice
#>

[cmdletbinding()]

param
(
    $DeviceID
)

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "devices"
    
    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=deviceId eq '$DeviceID'"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value 

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

################################

Function Add-AADGroupMember(){

<#
.SYNOPSIS
This function is used to add an member to an AAD Group from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a member to an AAD Group registered with AAD
.EXAMPLE
Add-AADGroupMember -GroupId $GroupId -AADMemberID $AADMemberID
Returns all users registered with Azure AD
.NOTES
NAME: Add-AADGroupMember
#>

[cmdletbinding()]

param
(
    $GroupId,
    $AADMemberId
)

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "groups"
    
    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$GroupId/members/`$ref"

$JSON = @"

{
    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$AADMemberId"
}

"@

    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $Json -ContentType "application/json"

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}


####################################################
####################################################
####################################################
####################################################
####################################################

#region Authentication

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()


    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($User -eq $null -or $User -eq ""){

            #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            #Write-Host

            }

        $global:authToken = Get-AuthToken

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    #Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken

}

#endregion

####################################################
####################################################
####################################################
####################################################
####################################################


# Getting AAD group members

####################################################
####################################################
#Add the user source group name or group id
$AADGroup = "fd127058-bb16-4205-9921-511a385d353d"
#Add the destination group id
$AADDestGroupId = "ecbc2314-183e-473b-af5a-ad61f1deff89"
####################################################
####################################################

$GroupMembers = @()
$TargetGroup = Get-AADGroup -groupId $AADGroup -Members

foreach($user in $TargetGroup.members){
    $GroupMembers += $user.id
}

#Write-Host "AAD members" $GroupMembers  -ForegroundColor Green



####################################################


#Script Cycle

<#Write-Host
Write-Host "Checking if any Managed Devices are registered with Intune..." -ForegroundColor Cyan
Write-Host #>

#Gets all devices from Intune that are registered and managed
$Devices = Get-ManagedDevices
$AADDestGroup = Get-AADGroup -groupId $AADDestGroupId -Members

if($Devices){

    <#Write-Host "Intune Managed Devices found..." -ForegroundColor Yellow
    Write-Host #>

    # Filters Intune Devices by users in the target group
    $deviceFromTargetedUser = $Devices | where-Object {$_.userId -in $GroupMembers}

    <#Write-Host "Values of targeted USer" $deviceFromTargetedUser.azureADDeviceId -ForegroundColor Yellow
    Write-Host
    Write-Host "Members " $GroupMembers.userId #>

    foreach($deviceOK in $deviceFromTargetedUser){


        Write-Host "Adding user device" $deviceOK.deviceName "to AAD Group $AADGroup..." -ForegroundColor Yellow

        # Getting Device information from Azure AD Devices

        $AAD_Device = Get-AADDevice -DeviceID $deviceOK.azureADDeviceId       

        $AAD_Id = $AAD_Device.id

            #Checks if the device is already inside the group, if it's not, it will add to the destination group
            $deviceExists = $AADDestGroup.members | where-object {$_.id -eq $AAD_Id}
            if($deviceExists -or $deviceExists.Count -gt 0 ) {

                Write-Host "Device already exists in AAD Group..." -ForegroundColor Red

            }

            else {

                Write-Host "Adding Device to AAD Group..." -ForegroundColor Yellow

                Add-AADGroupMember -GroupId $AADDestGroupId -AADMemberId $AAD_Id

            }

        Write-Host

    }
}