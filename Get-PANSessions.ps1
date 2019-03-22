Function Get-PANSessions {
<#
.SYNOPSIS
  This will return the portion of the uri to authenticate based on a tag

.DESCRIPTION
  This will return the portion of the uri to authenticate based on a tag

.PARAMETER Addresses
    This is a set of addresses to run command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference a key and set of addresses

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.PARAMETER Large <NOT IMPLEMENTED>
   If set to true, will interate through filters to attempt to get as much data as possible.
     The API response appears to be limited to a specific number of items

.PARAMETER Filter
   The Filter to apply to the query

.EXAMPLE
    The example below gets session that have been active for more than an hour
    PS C:\> Get-PANSessions -Tag 'EdgeFirewalls' -Filter '<min-age>3600</min-age><type>flow</type><state>active</state><min-kb>1</min-kb>' | Out-GridView


.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PaloAltoNetworksScripts
    Last Edit: 2019-03-20
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
    [string]
    $Filter,

    [Parameter(Mandatory=$False)]
    [string[]]
    $Addresses,

    [Parameter(Mandatory=$False)]
    [string]
    $Key,

    [Parameter(Mandatory=$False)]
    [System.Management.Automation.PSCredential]
    $Credential
  )

  #Make Sure the filter has the outer XML tags
  If ($Filter.Length -gt 1 -and -not ($Filter -imatch '<filter>')) {
      $Filter = '<filter>'+$Filter+'</filter>'
  }

  #Get Data from panrc based on tag
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path
  If ($Addresses -eq '' -or $Addresses -eq $null) {
    $Addresses = $TagData.Addresses
  }

  #Grab the sessions from all the firewalls
  $Sessions = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=op&cmd=<show><session><all>$Filter</all></session></show>&"+$TagData.Auth)
    if ( $Response.response.status -eq 'success' ) {
      $Sessions = $Sessions + $Response.response.result.entry
      #Had a firewall return exactly 2048 results, so I found I need to chop up into smaller results to get all the data
      #if ($Sessions.count -eq 2048) { $Overloaded = $true }
      #If ($Large) {
      #  <nat>source|destination|both|none</nat>
      #  <protocol>6|17</protocol>
      #  <ssl-decrypt>yes|no</ssl-decrypt>
      #}
    }
  }

  #For some reason a firewall I was working on included session that were built during the query, filtering them out if the time is less than a minute
  if ((0+([xml]$Filter).filter.'min-age') -gt 60) {
    $i = 0
    While ($i -lt $Sessions.Count){
      $delta = ''
      $delta = New-TimeSpan -Start ([datetime]::parseexact(($Sessions[$i].'start-time').Substring(4,20).replace("  "," "),'MMM d HH:mm:ss yyyy', $null)) -End (Get-Date)
      if ( $delta.TotalMinutes -ge 1 ) {$Sessions[$i]}
      $i++
    }
  } else {
    $Sessions
  }
}
