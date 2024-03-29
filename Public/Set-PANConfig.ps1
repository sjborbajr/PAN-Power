Function Set-PANConfig {
<#
.SYNOPSIS
  This will set configuration based on the xml and path provided

.DESCRIPTION
  This will set configuration based on the xml and path provided

.PARAMETER XPath
    This is location from which to get the config

.PARAMETER Data
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
    The example below disables a rule called "Certbot to RPi"
    PS C:\> Set-PANConfig -Data  '<disabled>yes</disabled>' -XPath "/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Certbot to RPi']"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2022-12-29
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting
    Version 1.0.3 - Remove Direct Credential option
    Version 1.0.5 - Add SkipCertificateCheck for pwsh 6+
    Version 1.0.6 - added Edit config and commit and cert check skip for 5
    Version 1.0.8 - added target parameter

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$True)]   [string]    $XPath,
    [Parameter(Mandatory=$True)]   [string]    $Data,
    [Parameter(Mandatory=$False)]  [Switch]    $SkipCertificateCheck,
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
    [Parameter(Mandatory=$False)]  [string[]]  $Target,
    [Parameter(Mandatory=$False)]  [string[]]  $Addresses,
    [Parameter(Mandatory=$False)]  [string]    $Key
  )

  #Get Data from panrc based on tag
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path
  If ($Addresses -eq '' -or $null -eq $Addresses) {
    $Addresses = $TagData.Addresses
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

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $HashArguments = @{
      URI = "https://"+$Address+"/api/?type=config&action=set&xpath=$XPath&element=$Data&"+$Auth
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
