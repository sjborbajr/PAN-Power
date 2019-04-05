Function Get-PANConnectionsPerSecond {
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
