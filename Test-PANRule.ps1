Function Test-PANRule {
<#
.SYNOPSIS
  This will run the operations passed and retun the result in xml

.DESCRIPTION
  This runs the command test security-policy-match with the filters provided.

.PARAMETER Addresses
    This is a set of addresses to run the command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER from
    Source Zone

.PARAMETER to
    Destination Zone

.PARAMETER source
    Source IP address

.PARAMETER destination
    Destination IP address

.PARAMETER protocol
    IP protocol number, tcp = 6, udp = 17, icmp = 1, sctp = 132

.PARAMETER destination_port
    Destination port for tcp, udp, or sctp

.PARAMETER application
    Application that will eventually choosen

.PARAMETER source_user
    Source user if applicable

.PARAMETER category
    URL Category if applicable

.PARAMETER Show_All
    Flag to show all results

.PARAMETER Path
   Path to the file that has the tag data

.EXAMPLE
    The example below will return all rules that could match a ping packet from the inside to outside
    PS C:\> $result = Test-PANRule -from "Inside" -to "Outside" -source '192.0.2.2' -destination '1.1.1.1' -protocol 1 -category 'any' -Show_All

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PaloAltoNetworksScripts
    Last Edit: 2019-03-29
    Version 1.0 - initial release

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)] [string]   $Tag,
    [Parameter(Mandatory=$False)] [string]   $Path = '',
    [Parameter(Mandatory=$False)] [string[]] $Addresses,
    [Parameter(Mandatory=$False)] [string]   $Key,
    [Parameter(Mandatory=$False)] [System.Management.Automation.PSCredential] $Credential,
    [Parameter(Mandatory=$False)] [string]   $from,
    [Parameter(Mandatory=$False)] [string]   $to,
    [Parameter(Mandatory=$true)]  [string]   $source,
    [Parameter(Mandatory=$true)]  [string]   $destination,
    [Parameter(Mandatory=$true)]  [int]      $protocol,
    [Parameter(Mandatory=$False)] [int]      $destination_port,
    [Parameter(Mandatory=$False)] [string]   $application,
    [Parameter(Mandatory=$False)] [string]   $source_user,
    [Parameter(Mandatory=$False)] [string]   $category,
    [Parameter(Mandatory=$False)] [Switch]   $Show_All
  )

  #Get Data from panrc based on tag
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path
  If ($Addresses -eq '' -or $null -eq $Addresses) {
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

  #Build the command
  $Command = ''
  If ($from)             { $Command =             "$Command<from>$from</from>"                         }
  If ($to)               { $Command =               "$Command<to>$to</to>"                             }
  If ($source)           { $Command =           "$Command<source>$source</source>"                     }
  If ($destination)      { $Command =      "$Command<destination>$destination</destination>"           }
  If ($protocol)         { $Command =         "$Command<protocol>$protocol</protocol>"                 }
  If ($destination_port) { $Command = "$Command<destination-port>$destination_port</destination-port>" }
  If ($application)      { $Command =      "$Command<application>$application</application>"           }
  If ($source_user)      { $Command =      "$Command<source-user>$source_user</source-user>"           }
  If ($category)         { $Command =         "$Command<category>$category</category>"                 }
  If ($Show_All)         { $Command =         "$Command<show-all>yes</show-all>"                       }
  $command = "<test><security-policy-match>$Command</security-policy-match></test>"

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=op&cmd=$Command&"+$Auth)
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