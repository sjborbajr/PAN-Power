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

.PARAMETER StorageMeathod
   API_Key - Clear key like pan-python
   SecureAPI_Key - Secured with Windows secure string tied to the user/pc
   SecureUserAndPass - Just store the username and password in windows secure string, but use keygen to validate password
   <not implemented> SharedSecureAPI_Key - Secured, but using a shared secret that can be stored for the user/pc combination

.PARAMETER Addresses
    This is a set of addresses to run the command on, The firewalls must have the same master key for this to work

.PARAMETER Key
    This is a key to just use

.PARAMETER Credential
    This is a user account to just use

.PARAMETER Tag
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.EXAMPLE
    The example below get a Key from 192.0.2.1 and stores it in a group called AllEdge along with the three addresses associated
    PS C:\> Invoke-PANKeyGen -Tag 'AllEdge' -Addresses @('192.0.2.1','198.51.100.1','203.0.113.1')

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting

#>

  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)][ValidateSet('API_Key','SecureAPI_Key','SecureUserAndPass')]
                                   [string]    $StorageMeathod = 'SecureAPI_Key',
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
    [Parameter(Mandatory=$False)]  [string[]]  $Addresses,
    [Parameter(Mandatory=$False)]  [string]    $Key,
    [Parameter(Mandatory=$False)]  [System.Management.Automation.PSCredential]   $Credential
  )

  #Make sure the addresses variable is an array of strings
  If ($Addresses.GetType().Name -eq 'String') {$Addresses = @($Addresses)}

  #Get the Path if not supplied
  if ($Path -eq '') {
    if (Test-Path "panrc.xml") {
      $Path = "panrc.xml"
    } else {
      $path = $env:USERPROFILE+"\panrc.xml"
    }
  }

  #Get the key
  $Response = Invoke-RestMethod (("https://"+$Addresses[0]+"/api/?type=keygen&user="+$Credential.username+"&password="+$Credential.GetNetworkCredential().password))
  if ( $Response.response.status -eq 'success' ) {
    $API_Key = $Response.response.result.key

    #Format
    Switch ($StorageMeathod){
      'API_Key' {
        $Data = @{$Tag = @{Type = 'API_Key'; Addresses=$Addresses; API_Key=$API_Key; TimeStamp=(Get-Date)}}
      }
      'SecureAPI_Key' {
        $Data = @{$Tag = @{Type = 'SecureAPI_Key'; Addresses=$Addresses; API_Key=(New-Object System.Management.Automation.PSCredential -ArgumentList 'API_Key', ($API_Key | ConvertTo-SecureString -AsPlainText -Force)); TimeStamp=(Get-Date); Combo=@{USERNAME=$env:USERNAME;COMPUTERNAME=$env:COMPUTERNAME}}}
      }
      'SecureUserAndPass' {
        $Data = @{$Tag = @{Type = 'SecureUserAndPass'; Addresses=$Addresses; Credential=$Credential; TimeStamp=(Get-Date); Combo=@{USERNAME=$env:USERNAME;COMPUTERNAME=$env:COMPUTERNAME}}}
      }
      'SharedSecureAPI_Key' {
        #not implemented - notes on how I can do it
        #$plainText = "Some Super Secret Password"
        #$key = Set-Key "AGoodKeyThatNoOneElseWillKnow"
        #$encryptedTextThatIcouldSaveToFile = Set-EncryptedData -key $key -plainText $plaintext
        #$encryptedTextThatIcouldSaveToFile
        #507964ed3a197b26969adead0212743c378a478c64007c477efbb21be5748670a7543cb21135ec324e37f80f66d17c76c4a75f6783de126658bce09ef19d50da
        #$DecryptedText = Get-EncryptedData -data $encryptedTextThatIcouldSaveToFile -key $key
        #$DecryptedText
        #Some Super Secret Password
      }
    }

    #Store - Check to see if xml exists, then if entry exists, and create, replace, or add as appropriate
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
    $Response.response.status
    Return
  } else {
    $Response.response
    Return
  }
}