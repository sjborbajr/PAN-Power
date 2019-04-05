Function Get-PANConfig {
<#
.SYNOPSIS
  This will get the config and retun the result in xml

.DESCRIPTION
  This will get the config based on the path requested and retun the result in xml

.PARAMETER XPath
    This is location from which to get the config

.PARAMETER Running
    If this is flagged, get the active instead of candidate configuration

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
    The example below retrieves the entire config from the default firewall and exports it in xml to a file
    PS C:\> (Get-PANConfig).config.OuterXml | Out-File "Config.xml"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0   - initial release
    Version 1.0.1 - Adding notes and updating some error handling
    Version 1.0.2 - Updating descriptions and formatting

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]  [string]    $XPath,
    [Parameter(Mandatory=$False)]  [Switch]    $Running,
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
  
  #Action of show is the active running config and get returns the candidate config
  If ($Running) { $Action = "show" } else { $Action = "get" }

  #Handle blank XPath to report full config
  If ($XPath)   { $XPath = "&xpath=$XPath" } else {$XPath = "&xpath=/config"}

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=config&action=$Action$XPath&"+$Auth)
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
﻿Function Get-PANConnectionsPerSecond {
<#
.SYNOPSIS
  This will query a firewall for it's interfaces and connection per second information and return summary information

.DESCRIPTION
  The script uses the API to connect to the firewall and pull a table of zones, then for the specified time will poll the firewall for cps counters

.PARAMETER Interval
  The rate in seconds at which the firewalls will be polled

.PARAMETER Duration
  The duration in minutes for the polling to run

.PARAMETER AsJob
  <NOT IMPLEMENTED> run in jobs queues (scale out)

.PARAMETER Addresses
    This is a set of addresses to run command on to override info from panrc.mxl

.PARAMETER Key
    This is a key to override info from panrc.mxl

.PARAMETER Credential
    This is a user account to use and override info from panrc.mxl

.PARAMETER Tag
    This is the shortname to use to reference a key and set of addresses from panrc.xml

.PARAMETER Path
   Path to the panrc file to override default search

.EXAMPLE
    The example below will query the default firewall for connections persecond information for 5 minutes at a 10 second interval
    PS C:\> Get-PANConnectionsPerSecond -Tag '' -Duration 5 -Interval 10


.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-03-22
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
    [int]
    $Duration = 5,

    [Parameter(Mandatory=$False)]
    [int]
    $Interval = 10,

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

  #Get Data from panrc based on tag
  $TagData = Get-PANRCTagData -Tag $Tag -Path $Path
  If ($Addresses -eq '' -or $Addresses -eq $null) {
    $Addresses = $TagData.Addresses
  }

  $cmd = '<show><counter><interface>all</interface></counter></show>'
  $zone_cmd = '<show><interface>all</interface></show>'

  ##########
  $Zones = (Invoke-PANOperation -Command $zone_cmd -Tag $Tag -Addresses $Addresses -Path $Path -Key $Key -Credential $Credential).ifnet.entry | ? { $_.Zone.Length -gt 0 } | Select "Zone","Name"

  $Result = @()
  $LoopTill = (Get-Date) + (New-TimeSpan -Minutes $Duration)
  $NextPoll = Get-Date
  While ( $LoopTill -gt (Get-Date) -and $NextPoll -lt $LoopTill ) {
    $DateTime = Get-Date
    Write-Progress -id 1 -Activity "Gathering Data" -SecondsRemaining ((New-TimeSpan $DateTime $LoopTill).TotalSeconds) -PercentComplete (($Duration-(New-TimeSpan $DateTime $LoopTill).TotalMinutes)*100/$Duration)
    $Response = Invoke-PANOperation -Command $cmd -Tag $Tag -Addresses $Addresses -Path $Path -Key $Key -Credential $Credential
    $Raw = $Response.ifnet.ifnet.entry | select "Name","tcp_conn","udp_conn","sctp_conn","other_conn"
      foreach ($row in $Raw) { 
        $Zone = $Zones | ? {$_.Name -eq $Row.Name} | select -First 1 -Property 'zone' -ExpandProperty 'zone'
        $row | Add-Member 'TimeStamp' $DateTime
        $row | Add-Member 'Zone'      $Zone
      }
      $Result = $Result + $Raw
    $Elapse   = New-TimeSpan $DateTime (Get-Date)
    $NextPoll = (Get-Date).AddMilliseconds($Interval*1000 - $Elapse.TotalMilliseconds - 10)
    if ( $NextPoll -lt $LoopTill ) {
      Write-Progress -id 1 -Activity "Sleeping" -SecondsRemaining ((New-TimeSpan (Get-date) $LoopTill).TotalSeconds) -PercentComplete (($Duration-(New-TimeSpan $DateTime $LoopTill).TotalMinutes)*100/$Duration)
      Start-Sleep -Milliseconds (($Interval*1000) - $Elapse.TotalMilliseconds - 10)
    }
  }

  #Group connection data for zones with multiple interfaces together for ZPP
  $Grouped = $result | Group-Object Zone,TimeStamp | % {
    $By = $_.name -split ', '
    #discard interfaces without zones
    if ($By.Count -gt 1) {
      [pscustomobject] @{
        'Zone'       = $By[0]
        'TimeStamp'  = $By[1]
        'tcp_conn'   = ($_.group | Measure-Object -Property 'tcp_conn'   -Sum).sum
        'udp_conn'   = ($_.group | Measure-Object -Property 'udp_conn'   -Sum).sum
        'sctp_conn'  = ($_.group | Measure-Object -Property 'sctp_conn'  -Sum).sum
        'other_conn' = ($_.group | Measure-Object -Property 'other_conn' -Sum).sum
      }
    }
  }

  $Statistics = Foreach ($Zone in ($Zones | select -Unique 'Zone')) {
    $ZoneData = $Grouped | ? { $_.Zone -eq $Zone.zone }
    $Measure_TCP   = Measure-Object-2 ( $ZoneData | select -Property 'tcp_conn'   -ExpandProperty 'tcp_conn')
    $Measure_UDP   = Measure-Object-2 ( $ZoneData | select -Property 'udp_conn'   -ExpandProperty 'udp_conn')
    $Measure_SCTP  = Measure-Object-2 ( $ZoneData | select -Property 'sctp_conn'  -ExpandProperty 'sctp_conn')
    $Measure_Other = Measure-Object-2 ( $ZoneData | select -Property 'other_conn' -ExpandProperty 'other_conn')
    [pscustomobject] @{
      'Zone'      = $Zone.zone
      'Start'     = $ZoneData[0].TimeStamp
      'Stop'      = $ZoneData[($ZoneData.Count-1)].TimeStamp
      'tcp_max'   = $Measure_TCP.Maximum
      'tcp_avg'   = $Measure_TCP.Average
      'tcp_dev'   = $Measure_TCP.StandardDeviation
      'udp_max'   = $Measure_UDP.Maximum
      'udp_avg'   = $Measure_UDP.Average
      'udp_dev'   = $Measure_UDP.StandardDeviation
      'sctp_max'  = $Measure_SCTP.Maximum
      'sctp_avg'  = $Measure_SCTP.Average
      'sctp_dev'  = $Measure_SCTP.StandardDeviation
      'other_max' = $Measure_Other.Maximum
      'other_avg' = $Measure_Other.Average
      'other_dev' = $Measure_Other.StandardDeviation
    }
  }
  $Statistics
}
function Measure-Object-2 {
  [CmdletBinding()]
  param (
    [double[]]$numbers
  )
  $Return = $numbers | Measure-Object -Average -Sum -Maximum -Minimum
  $sqdiffs = $numbers | foreach {[math]::Pow(($psitem - $Return.Average), 2)}
  $StandardDeviation = [math]::Round([math]::Sqrt( ($sqdiffs | Measure-Object -Average | select -ExpandProperty Average) ), 3)
  $Return | Add-Member 'StandardDeviation' $StandardDeviation
  $Return
}
Function Get-PANRCTagData {
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
    This is the shortname to use to reference auth information and addresses

.PARAMETER Path
   Path to the file to store data, check current directory, otherwise use profile directory

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting

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
      $Path = $env:USERPROFILE+"\panrc.xml"
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
        if ($Data.Combo.USERNAME -eq $env:USERNAME -and $Data.Combo.COMPUTERNAME -eq $env:COMPUTERNAME ) {
          $Return = @{'Auth' = 'key='+$Data.API_Key.GetNetworkCredential().password; 'Addresses'=$Data.Addresses}
        } else {
          #Key stored by different computer/user
        }
      }
      'SecureUserAndPass' {
        if ($Data.Combo.USERNAME -eq $env:USERNAME -and $Data.Combo.COMPUTERNAME -eq $env:COMPUTERNAME ) {
          $Return = @{'Auth' = 'user='+$Data.API_Key.UserName+'password='+$Data.API_Key.GetNetworkCredential().password; 'Addresses'=$Data.Addresses}
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
﻿Function Get-PANSessions {
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
}﻿Function Invoke-PANOperation {
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

.PARAMETER Credential
    This is a user account to just use

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

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]  [string]    $Command,
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

  #Run the command and get the results
  $Type = "op"
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=$Type&cmd=$Command&"+$Auth)
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
﻿Function Set-PANConfig {
<#
.SYNOPSIS
  This will set configuration based on the xml and path provided

.DESCRIPTION
  This will set configuration based on the xml and path provided

.PARAMETER XPath
    This is location from which to get the config

.PARAMETER Data
    This is location from which to get the config

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
    The example below disables a rule called "Certbot to RPi"
    PS C:\> Set-PANConfig -Data  '<disabled>yes</disabled>' -XPath "/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Certbot to RPi']"

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$True)]   [string]    $XPath,
    [Parameter(Mandatory=$True)]   [string]    $Data,
    [Parameter(Mandatory=$False)]  [string]    $Tag,
    [Parameter(Mandatory=$False)]  [string]    $Path = '',
    [Parameter(Mandatory=$False)]  [string[]]  $Addresses,
    [Parameter(Mandatory=$False)]  [string]    $Key,
    [Parameter(Mandatory=$False)]  [System.Management.Automation.PSCredential]   $Credential
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

  #Run the command and get the results
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=config&action=set&xpath=$XPath&element=$Data&"+$Auth)
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
﻿Function Test-PANRule {
<#
.SYNOPSIS
  This will run the operations passed and retun the result in xml

.DESCRIPTION
  This runs the command test security-policy-match with the filters provided.

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
    The example below will return all rules that could match a ping packet from the inside to outside
    PS C:\> $result = Test-PANRule -from "Inside" -to "Outside" -source '192.0.2.2' -destination '1.1.1.1' -protocol 1 -category 'any' -Show_All

.NOTES
    Author: Steve Borba https://github.com/sjborbajr/PAN-Power
    Last Edit: 2019-04-05
    Version 1.0 - initial release
    Version 1.0.1 - Updating descriptions and formatting

#>
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$False)]  [string]    $from,
    [Parameter(Mandatory=$False)]  [string]    $to,
    [Parameter(Mandatory=$true)]   [string]    $source,
    [Parameter(Mandatory=$true)]   [string]    $destination,
    [Parameter(Mandatory=$true)]   [int]       $protocol,
    [Parameter(Mandatory=$False)]  [int]       $destination_port,
    [Parameter(Mandatory=$False)]  [string]    $application,
    [Parameter(Mandatory=$False)]  [string]    $source_user,
    [Parameter(Mandatory=$False)]  [string]    $category,
    [Parameter(Mandatory=$False)]  [Switch]    $Show_All,
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
  $Type = "op"
  $Return = @()
  ForEach ($Address in $Addresses) {
    $Response = Invoke-RestMethod ("https://"+$Address+"/api/?type=$Type&cmd=$Command&"+$Auth)
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