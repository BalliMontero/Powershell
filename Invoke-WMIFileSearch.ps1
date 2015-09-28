function New-IPv4RangeFromCIDR 
{
    param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
				   $Network
    )
    # Extract the portions of the CIDR that will be needed
    $StrNetworkAddress = ($Network.split('/'))[0]
    [int]$NetworkLength = ($Network.split('/'))[1]
    $NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
    $IPLength = 32-$NetworkLength
    [Array]::Reverse($NetworkIP)
    $NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
    $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join '.')).Address
    $StartIP = $NetworkIP +1
    $EndIP = $NetworkIP + $NumberOfIPs
    # We make sure they are of type Double before conversion
    If ($EndIP -isnot [double])
    {
        $EndIP = $EndIP -as [double]
    }
    If ($StartIP -isnot [double])
    {
        $StartIP = $StartIP -as [double]
    }
    # We turn the start IP and end IP in to strings so they can be used.
    $StartIP = ([System.Net.IPAddress]$StartIP).IPAddressToString
    $EndIP = ([System.Net.IPAddress]$EndIP).IPAddressToString
    New-IPv4Range $StartIP $EndIP
}

<#
.Synopsis
   WMI File Searcher over Windows RPC Ports (TCP 135)
.DESCRIPTION
   WMI File Searcher over Windows RPC Ports (TCP 135)
.EXAMPLE
   Invoke-WMIFileSearchIP -IPAddress 172.16.0.10
.EXAMPLE
   Invoke-WMIFileSearchIPRangeCIDR -IPRangeCIDR 172.16.0.10/24
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-WMIFileSearchIP 
{
     param
     (
         [Object]
         $IPAddress,
         [Object]
         $Creds
     )

    if (!$Creds){
    $getcreds = Get-Credential
    }else
    {
    $getcreds = $Creds
    }

    $ping = New-Object System.Net.NetworkInformation.Ping
    if (($ping.send($IPAddress, 10)).Status-eq 'Success')
    {
        Write-Host `n'Host is alive: ' $IPAddress

        $wmiquery = "SELECT * FROM CIM_DataFile WHERE Drive ='C:' AND Path='\\windows\\' AND Extension='exe' AND CreationDate > '05/01/2015' "

        Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) | where-object Name -match '[a-z][a-z][a-z][a-z][a-z][a-z][a-z][a-z].exe' |foreach {Write-Host $_.Name}
    }   
}

<#
.Synopsis
   WMI File Searcher over Windows RPC Ports (TCP 135)
.DESCRIPTION
   WMI File Searcher over Windows RPC Ports (TCP 135)
.EXAMPLE
   Invoke-WMIFileSearchIP -IPAddress 172.16.0.10
.EXAMPLE
   Invoke-WMIFileSearchIPRangeCIDR -IPRangeCIDR 172.16.0.10/24
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-WMIFileSearchIPRangeCIDR
{
     param
     (
         [Object]
         $IPRangeCIDR
     )
     $getcreds = Get-Credential

     $iprangefull = New-IPv4RangeFromCIDR $IPRangeCIDR
     foreach ($ip in $iprangefull) {

     Invoke-WMIFileSearchIP -IPAddress $ip -Creds $getcreds

     }
     
 
}

<#
Other WMI CIM_DataFile Properies

- Drive
- Path
- Extension
- FileName
- FileSize
- CreationDate


#>
