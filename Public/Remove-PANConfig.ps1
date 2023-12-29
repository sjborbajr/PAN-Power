Function Remove-PANConfig {
<#
.SYNOPSIS
  This will remove the config at at XPath

.DESCRIPTION
  This will get the config based on the path requested and retun the result in xml

.PARAMETER XPath
    This is location from which to get the config

.PARAMETER Target
    This parameter allows you to redirect queries through Panorama to a managed firewall

.PARAMETER Addresses
    This is a set of addresses to run the command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file that has the tag data

.EXAMPLE
    The example below retrieves the entire config from the default firewall and exports it in xml to a file
    PS C:\> (Get-PANConfig).config.OuterXml | Out-File "Config.xml"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2022-12-29
    Version 1.0.7 - added remove config cmdlet
    Version 1.0.8 - added target parameter
    
#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]  [string]    $XPath,
    [Parameter(Mandatory=$False)]  [Switch]    $SkipCertificateCheck,
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
    [Parameter(Mandatory=$False)]  [string[]]  $Target,
    [Parameter(Mandatory=$False)]  [string[]]  $Addresses,
    [Parameter(Mandatory=$False)]  [string]    $Key
)

  #Get Data from panrc based on tag, an empty tag is "ok" and returns data
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path

  #If addresses were not passed, use addresses from panrc
  If ($Addresses -eq '' -or $null -eq $Addresses) {
    If ($TagData.Addresses) {
      $Addresses = $TagData.Addresses
    } else {
      "No Addresses Found"
      Return
    }
  }

  #Use other key if passed
  If ($Key.Length -gt 0) {
    $Auth = "key=$Key"
  } else {
    If ($TagData.Auth) {
      $Auth = $TagData.Auth
    } else {
      "No Authentication Information Found"
      return
    }
  }
  
  $Action = "delete"

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $HashArguments = @{
      URI = "https://"+$Address+"/api/?type=config&action=$Action&XPath=$XPath&"+$Auth
    }
    If ($Target) {
      $HashArguments['URI'] += "&target=$Target"
    }
    If ($SkipCertificateCheck) {
      If ($Host.Version.Major -ge 6) {
        $HashArguments += @{SkipCertificateCheck = $True}
      } else { Ignore-CertificateValidation }
    }
    $Response = Invoke-RestMethod @HashArguments
    if ( $Response.response.status -eq 'success' ) {
      $Return = $Return + $Response.response
    } else {
      $Return = $Return + $Response.response
      If (1 -eq 2) { 
        #Need flag to determine if we should quit on first error
        $Return
        Return
      }
    }
  }

  #Pass the data back
  $Return
  Return
}
