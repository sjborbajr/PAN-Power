Function Invoke-PANOperation {
<#
.SYNOPSIS
  This will run PAN-OS operation commands and retun the result in xml

.DESCRIPTION
  This runs the operation command passed, to find what operation are possible, ssh to firewall and use "debug cli on" and run command to find the syntax to use.

.PARAMETER Command
    This is the operation command you want to run

.PARAMETER Addresses
    This is a set of addresses to run the command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file that has the tag data

.EXAMPLE
    The example below retrieves the BGP rib table from the edge firewalls
    PS C:\> $BGP_Routes = Invoke-PANOperation -Command '<show><routing><protocol><bgp><loc-rib/></bgp></protocol></routing></show>' -Tag 'EdgeGroup'

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting
    Version 1.0.3 - Remove Direct Credential option
    Version 1.0.5 - Add SkipCertificateCheck for pwsh 6+
    Version 1.0.6 - added Edit config and commit and cert check skip for 5

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$True)]   [string]    $Command,
    [Parameter(Mandatory=$False)]  [Switch]    $SkipCertificateCheck,
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
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

  #Run the command and get the results
  $Type = "op"
  $Return = @()
  ForEach ($Address in $Addresses) {
    $HashArguments = @{
      URI = "https://"+$Address+"/api/?type=$Type&cmd=$Command&"+$Auth
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
