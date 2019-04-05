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
