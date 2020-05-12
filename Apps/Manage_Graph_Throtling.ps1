
<#

.COPYRIGHT
Copyright (c) Ricardo Marramaque. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

Autor: Ricardo Marramaque
Version: 1.0

This script will issue a high ammount of Graph calls to result in throttling 
and exemplify best practices on such situations. 

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

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

        $AadModule = Get-Module -Name "AzureAD" -ListAvailable

        if ($null -eq $AadModule) {
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
        }

        if ($null -eq $AadModule) {
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
                # Checking if there are multiple versions of the same module found

                if($AadModule.count -gt 1){
                    $aadModule = $AadModule | select -Unique
                }

            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
        }

        else {
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
        }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"

        try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

        $MethodArguments = [Type[]]@("System.String", "System.String", "System.Uri", "Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior", "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier")
        $NonAsync = $AuthContext.GetType().GetMethod("AcquireToken", $MethodArguments)

            if ($null -ne $NonAsync){
                $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, [Uri]$redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto, $userId)
            }
            else {
                $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, [Uri]$redirectUri, $platformParameters, $userId).Result 
            }

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

##################################################

Function Get-GraphRecursive(){

    ## Gets the next link of response when there is over 100 objects

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $uri
    )

    $result = @();

    try{
        $response = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get);
        $result += $response.value;

        if($response.'@odata.nextLink'){
            $result += Get-GraphRecursive -uri $response.'@odata.nextLink'
        }
        
        return $result;
        
    }catch{
        Write-Host "Exception while obtaing all objects with URI:`n" -f Red
        Write-Host "$uri`n" -f Red
        $_.Exception
    };
}

Function Get-GraphURIwithRetry(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $uri,
        [Parameter(Mandatory=$true)]
        $method,
        $body
    )

    try
    {
        if($body){
            $bodyJson = $body | ConvertTo-Json
            $res = Invoke-WebRequest -Uri $uri -Headers $authToken -Body $bodyJson -ContentType "application/json" -Method $method; 
        }else{
            $res = Invoke-WebRequest -Uri $uri -Headers $authToken -Method $method; 
        }
        
        return $res.Content | ConvertFrom-Json
    }
    catch
    {
        # Although many properties can be accessed directly, the Headers is
        # an Hashtable, as such we need to get the value by key. 

        $errorCode = $_.Exception.Response.StatusCode
        $requestID = $_.Exception.Response.Headers['request-id']
        $retryAfter = $_.Exception.Response.Headers['Retry-After']
        $msDiagnostic = $_.Exception.Response.Headers['x-ms-ags-diagnostic']
        $errorDate = $_.Exception.Response.Headers['Date']

        if($errorCode -eq 429){
            Write-Host "[429] Waiting $retryAfter seconds before retrying";
            start-sleep -Seconds $($retryAfter + 1);
            return Get-GraphURIwithRetry -uri $uri -method $method -body $body;

        }elseif($errorCode -gt 500){
            Write-Host "Something went wrong..."
            Write-Host $_.Exception.Message
            Write-Host "Error code: $errorCode"
            Write-Host "Request-ID: $requestID"
            Write-Host "Date: $errorDate"
            Write-Host "Response URI: $($_.Exception.Response.ResponseUri)"
        }
    }
}


######################### Functions END ###########################

############################ Logic ###################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()
    
    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
    if($TokenExpires -le 0){
    
        write-host "Authentication Token expired" $TokenExpires "minutes ago `n" -ForegroundColor Yellow
    
        # Defining User Principal Name if not present
        if($null -eq $User -or $User -eq ""){
            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
        }
    
        $global:authToken = Get-AuthToken -User $User
    }
}

# Authentication doesn't exist, calling Get-AuthToken function
else {
    
    if($null -eq $User -or $User -eq ""){
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
}

#endregion

####################################################

# The Intune device id to perform the test
# WARNING: This script will modify the management name of this device
$deviceID = "2ad1873d-5399-475b-8055-48d9331bf512" 

write-host "Starting test..." -f Yellow

$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceID"

$stop = $false
$count = 1
while(-not $stop) {

    $body = @{
        "@odata.context" = "https://graph.microsoft.com/beta/$metadata#deviceManagement/managedDevices/$entity";
        "managedDeviceName" = "GraphTest$count";
    }

    $res = Get-GraphURIwithRetry -uri $uri -body $body -method Patch;
    Write-Host "Retry $count";
    $count++
}

write-host "Test finished..." -f Yellow
Write-host

