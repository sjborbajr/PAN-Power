Function Invoke-PANOperation {
<#
.SYNOPSIS
  This will run the operations passed and retun the result in xml

.DESCRIPTION
  This runs the operation passed, do find what operations are possible, use "debug cli on" and run command not in 

.PARAMETER Addresses
    This is a set of addresses to run command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Command
    This is the operation command you want to run

.PARAMETER Path
   Path to the file that has the tag data

.EXAMPLE
    The example below does blah
    PS C:\> <Example>

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

    [Parameter(Mandatory=$False)]
    [string]
    $Command,

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

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=op&cmd=$Command&"+$TagData.Auth)
    if ( $Response.response.status -eq 'success' ) {
      $Return = $Return + $Response.response.result.entry
    }
  }
  $Return
}
