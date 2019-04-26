Function Get-PANRCTagData {
<#
.SYNOPSIS
  This will return the portion of the uri to authenticate based on a tag

.DESCRIPTION
  This will return the portion of the uri to authenticate based on a tag

 StorageMeathod:
   API_Key - Clear key like pan-python
   SecureAPI_Key - Secured with Windows secure string tied to the user/pc
   <not implemented> SharedSecureAPI_Key - Secured, but using a shared secret that can be stored for the user/pc combination

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting
    Version 1.0.4 - Update to use HOME on linux

#>

  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]    [string]    $Tag,
    [Parameter(Mandatory=$False)]    [string]    $Path = ''
  )

  #Get the Path if not supplied
  if ($Path -eq '' -or $Path.Length -le 0) {
    if (Test-Path "panrc.xml") {
      $Path = "panrc.xml"
    } else {
      if ($env:USERPROFILE) {
        $Path = $env:USERPROFILE+"\panrc.xml"
      } elseif ($env:HOME) {
        $Path = $env:HOME+"\panrc.xml"
      } else {
        $Path = (pwd).path+"\panrc.xml"
      }
    }
  }

  #Get data out of file
  $Data = ((Import-Clixml $Path)['Tags'])[$Tag]

  If ($Data) {
    #Format
    Switch ($Data.Type){
      'API_Key' {
        $Return = @{'Auth' = 'key='+$Data.API_Key; 'Addresses'=$Data.Addresses}
      }
      'SecureAPI_Key' {
        If ($env:COMPUTERNAME) {$ComputerName=$env:COMPUTERNAME} elseif ($env:HOSTNAME) {$ComputerName=$env:HOSTNAME} else {$ComputerName=''}
        if ($Data.Combo.USERNAME -eq $env:USERNAME -and $Data.Combo.COMPUTERNAME -eq $ComputerName ) {
          $Return = @{'Auth' = 'key='+$Data.API_Key.GetNetworkCredential().password; 'Addresses'=$Data.Addresses}
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
    "Tag Not found in panrc"
    return
  }
}
