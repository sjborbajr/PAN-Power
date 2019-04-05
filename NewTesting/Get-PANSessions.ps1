Function Get-PANSessions {
<#
.SYNOPSIS
  This will querry the active session table based on the filter provided

.DESCRIPTION
  This will querry the active session table based on the filter provided

.PARAMETER Filter
   The Filter to apply to the query

.PARAMETER Addresses
    This is a set of addresses to run the command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file that has the tag data

.EXAMPLE
    The example below gets session that have been active for more than an hour
    PS C:\> Get-PANSessions -Tag 'EdgeFirewalls' -Filter '<min-age>3600</min-age><type>flow</type><state>active</state><min-kb>1</min-kb>' | Out-GridView


.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]  [string]    $Filter,
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
    [Parameter(Mandatory=$False)]  [string[]]  $Addresses,
    [Parameter(Mandatory=$False)]  [string]    $Key,
    [Parameter(Mandatory=$False)]  [System.Management.Automation.PSCredential]   $Credential
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

  #Use other authentication (credential/key), if passed
  if ($Credential) {
    $Auth = 'user='+$Credential.UserName+'password='+$Credential.GetNetworkCredential().password
  } Else {
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
  }

  #Make Sure the filter has the outer XML tags
  If ($Filter.Length -gt 1 -and -not ($Filter -imatch '<filter>')) {
      $Filter = '<filter>'+$Filter+'</filter>'
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
    } else {
      $Response.response
      Return
    }
  }

  #A firewall queeried sometimes includes sessions built during query, filtering if time is less than a minute and filter set min age greater than a minute
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
