Function Get-PANConfig {
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

.PARAMETER Running
    If this is flagged, get the active instead of candidate configuration

.PARAMETER Path
   Path to the panrc file that has the tag data

.EXAMPLE
    The example below retrieves the entire config from the default firewall and exports it in xml to a file
    PS C:\> (Get-PANConfig).config.OuterXml | Out-File "Config.xml"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PaloAltoNetworksScripts
    Last Edit: 2019-03-29
    Version 1.0   - initial release
    Version 1.0.1 - Adding notes and updating some error handling

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

    [Parameter(Mandatory=$False)]
    [string]
    $XPath,

    [Parameter(Mandatory=$False)]
    [Switch]
    $Running,

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

  If ($Running) { $Action = "show" } else { $Action = "get" }
  #Allowing blank XPath to report full config
  If ($XPath)   { $XPath = "&xpath=$XPath" } else {$XPath = "&xpath=/config"}
  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=config&action=$Action$XPath&"+$Auth)
    if ( $Response.response.status -eq 'success' ) {
      if ($Response.response.result.entry.Length -gt 0) {
        $Return = $Return + $Response.response.result.entry
      } else {
        $Return = $Return + $Response.response.result
      }
    } else {
      $Response.response
      Return
    }
  }
  $Return
  Return
}
