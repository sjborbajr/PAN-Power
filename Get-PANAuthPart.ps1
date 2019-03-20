Function Get-PANAuthPart {
<#
.SYNOPSIS
  This will return the portion of the uri to authenticate based on a tag

.DESCRIPTION
  This will return the portion of the uri to authenticate based on a tag

 StorageMeathod:
   API_Key - Clear key like pan-python
   SecureAPI_Key - Secured with Windows secure string tied to the user/pc
   SecureUserAndPass - Just store the username and password in windows secure string, but use keygen to validate password
   <not implemented> SharedSecureAPI_Key - Secured, but using a shared secret that can be stored for the user/pc combination

.PARAMETER Tag
    This is the shortname to use to reference a key and set of addresses

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.EXAMPLE
    The example below does blah
    PS C:\> <Example>

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
    $Path = ''
  )

  #Get the Path if not supplied
  if ($Path -eq '') {
    if (Test-Path "panrc.xml") {
      $Path = "panrc.xml"
    } else {
      $env:USERPROFILE+"\panrc.xml"
    }
  }

  #Get data out of file
  $Data = ((Import-Clixml $Path)['Tags'])[$Tag]
  
  If ($Data) {
    #Format
    Switch ($Data.Type){
      'API_Key' {
        $Return = 'key='+$Data.API_Key
      }
      'SecureAPI_Key' {
        if ($Data.Combo.USERNAME -eq $env:USERNAME -and $Data.Combo.COMPUTERNAME -eq $env:COMPUTERNAME ) {
          $Return = 'key='+$Data.API_Key.GetNetworkCredential().password
        } else {
          #Key stored by different computer/user
        }
      }
      'SecureUserAndPass' {
        if ($Data.Combo.USERNAME -eq $env:USERNAME -and $Data.Combo.COMPUTERNAME -eq $env:COMPUTERNAME ) {
          $Return = 'user='+$Data.API_Key.GetNetworkCredential().password+'password='+$Data.API_Key.GetNetworkCredential().password
        } else {
          #Key stored by different computer/user
        }
      }
      'SharedSecureAPI_Key' {
        #not implemented
      }
    }
    $Return
  } Else {
    #Tag Not found in panrc
  }
}