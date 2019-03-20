Function Invoke-PANKeyGen {
<#
.SYNOPSIS
  This stores api keys tied to tags/addresses
  Remember, this is basically a encrypted representation of the username and password that a firewall with the same master key can decrypt and use, so if you change the password, this muct also change

.DESCRIPTION
  In pan-python, the keys are stored in the clear in a file called .panrc in the users home folder
  I like this idea, but windows allows me to store in a secure string format that allows only the user/pc combination to retrieve the key
    I want to allow users to colaborate/share keys it can be frustrating when using scheduled tasks and/or multiple PCs

  With this change in formatting, reusing the .panrc file would cause conflict, so I will use panrc.xml

.PARAMETER Credential
    This is the user account that will be used to create the key.

.PARAMETER Tag
    This is the shortname to use to reference a key and set of addresses

.PARAMETER Addresses
    This is a set of addresses to store with the Tag, the key with be generated against the first address
      The firewall must have the same master key for this to work

.PARAMETER StorageMeathod 
   Storage Meathod 1 - Clear key like pan-python
   Storage Meathod 2 - Secured with Windows secure string tied to the user/pc
   Storage Meathod 3 - Just store the username and password in windows secure string, but use keygen to validate password
   <not implemented> Storage Meathod 4 - Secured, but using a shared secret that can be stored for the user/pc combination

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.EXAMPLE
    The example below does blah
    PS C:\> <Example>
    
.NOTES
    Author: Steve Borba
    Last Edit: 2019-03-20
    Version 1.0 - initial release

#>

  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$True)]
    [System.Management.Automation.PSCredential]
    $Credential,

    [Parameter(Mandatory=$True)]
    [string[]]
    $Addresses,

    [Parameter(Mandatory=$False)]
    [string]
    $Tag,

    [Parameter(Mandatory=$False)]
    [ValidateSet(1,2,3)]
    [int]
    $StorageMeathod = 2,

    [Parameter(Mandatory=$False)]
    [string]
    $Path = ''
    
  )

  #Make sure the addresses variable is an array of strings
  If ($Addresses.GetType().Name -eq 'String') {$Addresses = @($Addresses)}

  #Get the key
  $Response = Invoke-RestMethod (("https://"+$Addresses[0]+"/api/?type=keygen&user="+$Credential.username+"&password="+$Credential.GetNetworkCredential().password))
  if ( $Response.response.status -eq 'success' ) {
    $API_Key = $Response.response.result.key

    #Get the Path if not supplied
    if ($Path -eq '') {
      if (Test-Path "panrc.xml") {
        $Path = "panrc.xml"
      } else {
        $env:USERPROFILE+"\panrc.xml"
      }
    }
    
    #Format
    Switch ($StorageMeathod){
      1 {
        $Data = @{$Tag = @{Type = 'API_Key'; Addresses=$Addresses; API_Key=$API_Key; TimeStamp=(Get-Date)}}
      }
      2 {
        $Data = @{$Tag = @{Type = 'SecureAPI_Key'; Addresses=$Addresses; API_Key=(New-Object System.Management.Automation.PSCredential -ArgumentList 'API_Key', ($API_Key | ConvertTo-SecureString -AsPlainText -Force)); TimeStamp=(Get-Date); Combo=@{USERNAME=$env:USERNAME;COMPUTERNAME=$env:COMPUTERNAME}}}
      }
      3 {
        $Data = @{$Tag = @{Type = 'SecureUserAndPass'; Addresses=$Addresses; Credential=$Credential; TimeStamp=(Get-Date); Combo=@{USERNAME=$env:USERNAME;COMPUTERNAME=$env:COMPUTERNAME}}}
      }
      4 {
        #not implemented
      }
    }
    
    #Store - Check to see if it already exists, replace, add, or create
    If (Test-Path $Path) {
      $FileData = Import-Clixml $Path
      If ($FileData.Tags) {
        If ($FileData.Tags[$Tag]) {
          #remove to allow replace
          $FileData.Tags.Remove($Tag)
        }
        $FileData.Tags = $FileData.Tags + $Data
      } else {
        $FileData = $FileData + @{Tags=$Data}
      }
    } else {
      $FileData = @{Tags=$Data}
    }
    $FileData | Export-Clixml $Path
  } Else {
    #Rest Method failed
  }
}
