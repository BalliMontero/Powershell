<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a Start and End IP.
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a Start and End IP.
.EXAMPLE
    Generating a list of IPs from CIDR

    Get-IPRange 192.168.1.0/24
    
.EXAMPLE
    Generating a list of IPs from Range

    Get-IPRange -Range 192.168.1.1-192.168.1.50
#>
function New-IPv4Range
{
  param(
    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
           $StartIP,
           
    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
           $EndIP      
  )
  
    # created by Dr. Tobias Weltner, MVP PowerShell
    $ip1 = ([System.Net.IPAddress]$StartIP).GetAddressBytes()
    [Array]::Reverse($ip1)
    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

    $ip2 = ([System.Net.IPAddress]$EndIP).GetAddressBytes()
    [Array]::Reverse($ip2)
    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

    for ($x=$ip1; $x -le $ip2; $x++) {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        $ip -join '.'
    }
}

<#
.Synopsis
    Generates a IP Address Objects for IPv4 and IPv6 Ranges.
.DESCRIPTION
    Generates a IP Address Objects for IPv4 and IPv6 Ranges given a ranges in CIDR or
    range <StartIP>-<EndIP> format.
.EXAMPLE
    PS C:\> New-IPvRange -Range 192.168.1.1-192.168.1.5

    Generate a collection of IPv4 Object collection for the specified range.

.EXAMPLE
   New-IPRange -Range 192.168.1.1-192.168.1.50 | select -ExpandProperty ipaddresstostring

   Get a list of IPv4 Addresses in a given range as a list for use in another tool.
#>
function New-IPRange
{
    [CmdletBinding(DefaultParameterSetName="CIDR")]
    Param(
        [parameter(Mandatory=$true,
        ParameterSetName = "CIDR",
        Position=0)]
        [string]$CIDR,

        [parameter(Mandatory=$true,
        ParameterSetName = "Range",
        Position=0)]
        [string]$Range   
    )
    if($CIDR)
    {
        $IPPart,$MaskPart = $CIDR.Split("/")
        $AddressFamily = ([System.Net.IPAddress]::Parse($IPPart)).AddressFamily

        # Get the family type for the IP (IPv4 or IPv6)
        $subnetMaskObj = [IPHelper.IP.Subnetmask]::Parse($MaskPart, $AddressFamily)
        
        # Get the Network and Brodcast Addressed
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessNetworkAddress($IPPart, $subnetMaskObj)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessBroadcastAddress($IPPart,$subnetMaskObj)
        
        # Ensure we do not list the Network and Brodcast Address
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::Increase($StartIP)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::Decrease($EndIP)
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
    elseif ($Range)
    {
        $StartIP, $EndIP = $range.split("-")
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
}

<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a CIDR.
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a CIDR.
.EXAMPLE
    Generating a list of IPs
    PS C:\> New-IPv4RangeFromCIDR -Network 192.168.1.0/29
    192.168.1.1
    192.168.1.2
    192.168.1.3
    192.168.1.4
    192.168.1.5
    192.168.1.6
    192.168.1.7
#>
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
function Invoke-WMIActivationIP 
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
        
        $wmiquery = "Select * From SoftwareLicensingProduct"
        $isActivated = Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) 
        $isActivated
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
function Invoke-WMIActivationIPRangeCIDR
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