Function Set-PANConfig {
<#
.SYNOPSIS
  This will run pull the config and retun the result in xml

.DESCRIPTION
  This pull configuration based on the path requested

.PARAMETER Addresses
    This is a set of addresses to get the config from, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses from the panrc file

.PARAMETER XPath
    This is location from which to get the config

.PARAMETER Data
    This is location from which to get the config

.PARAMETER Path
   Path to the panrc file that has the tag data

.EXAMPLE
    The example below disables a rule called "Certbot to RPi"
    PS C:\> Set-PANConfig -Data  '<disabled>yes</disabled>' -XPath "/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Certbot to RPi']"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PaloAltoNetworksScripts
    Last Edit: 2019-03-21
    Version 1.0 - initial release

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]
    [string]
    $Tag,

    [Parameter(Mandatory=$False)]
    [string]
    $Path = '',

    [Parameter(Mandatory=$False)]
    [string[]]
    $Addresses,

    [Parameter(Mandatory=$True)]
    [string]
    $XPath,

    [Parameter(Mandatory=$True)]
    [string]
    $Data,

    [Parameter(Mandatory=$False)]
    [string]
    $Key,

    [Parameter(Mandatory=$False)]
    [System.Management.Automation.PSCredential]
    $Credential
  )

  #Get Data from panrc based on tag
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path
  If ($Addresses -eq '' -or $Addresses -eq $null) {
    $Addresses = $TagData.Addresses
  }
  
  if ($Credential) {
    $Auth = 'user='+$Credential.UserName+'password='+$Credential.GetNetworkCredential().password
  } Else {
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
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=config&action=set&xpath=$XPath&element=$Data&"+$Auth)
    $Return = $Return + $Response.response
  }
  $Return
  Return
}
