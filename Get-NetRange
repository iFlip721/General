Function Get-NetRange{
    <#
        Author: Jeffrey Wills 856CPT 185COS VaANG Langley AFB
        TODO:
        [ ] Support range with -IpAddressStart -IpAddressEnd
    #>
    
    param(
        [ValidateScript({[IpAddress]$_})][String]$IpAddress,
        #[ValidateScript({[IpAddress]$_})][String]$StartIp,
        #[ValidateScript({[IpAddress]$_})][String]$EndIp,
        [ValidateRange(8,32)][Int32]$Cidr=24,
        [ValidateScript({[IpAddress]$_})][String]$NetworkMask,
        [Switch]$AddressesOnly,
        [Switch]$LargeNetWork,
        [switch]$ToDecimalValue,
        [Switch]$ToNetMask,
        [switch]$ToCidr
        )
    If($NetworkMask){
        $cidrCntr = 0
        $netBytes = ([IpAddress]$NetworkMask).GetAddressBytes()
        ForEach($byte in $netBytes){
            ForEach($pow in 8..0){
                If($byte -band [math]::pow(2,$pow)){
                    $cidrcntr++
                }
            }
        }
        $cidr = $cidrCntr
         $netMask = 0
        ForEach($i in 31..(32-$Cidr)){
            $netMask += [math]::Pow(2,$i)
        }
        If($ToCidr){
         return $cidr
        }
    }
    ElseIf($Cidr){
        $netMask = 0
        ForEach($i in 31..(32-$Cidr)){
            $netMask += [math]::Pow(2,$i)
        }
        If($ToNetMask){
            return ([IpAddress]$NetMask).IPAddressToString
        }
    }
    $hostAddresses = 0
    ForEach($i in (31-$Cidr)..0){
        $hostAddresses += [math]::Pow(2,$i)
    }

    $IpAddresses = @(0)*($hostAddresses+1)
    $hostAddresses--

    #Do Some Bitwise magic
    $fullMask = [IPAddress][UInt32]::MaxValue
    $hostMask = $netMask -bxor $fullMask.Address
    $netAddress =  [IpAddress](([Ipaddress]$netMask).Address -band ([Ipaddress]$IpAddress).Address)   
    $brodcastAddress = [IpAddress]($netAddress.Address -Bxor ([Ipaddress]$hostMask).Address)
    
    #Ip Addresses are in network order (big-endian), Ints/Uints are little-Endian
    #To calculate Network ranges, Ips are converted to Uint32 for easy decimal math 
    [Byte[]]$startBytes = $netAddress.GetAddressBytes()
    [Array]::Reverse($startBytes)
    [Byte[]]$endBytes = $brodcastAddress.GetAddressBytes()
    [Array]::Reverse($endBytes)
    [Uint32]$startInt = [System.BitConverter]::ToUint32($startBytes,0)
    [Uint32]$endInt = [System.BitConverter]::ToUint32($endBytes,0)   

    If($ToDecimalValue){
        [Byte[]]$addrBytes = ([Ipaddress]$IpAddress).GetAddressBytes()
        [Array]::Reverse($addrBytes)
        return [System.BitConverter]::ToUint32($addrBytes,0)
    }

    #NOTE can't iterate Uint32 like Int32 i.e (x..y) or using [system.linq.Enumerable]::Range(x,y)
    If($cidr -le 19 -And !$LargeNetWork){$endInt = $startInt + 10 ; Write-Host All Addresses Truncated to first 10 Addresses. If All Host Addresses `
    Are required Use `-LargeNetwork `nFor networks between /8 and /19, It takes significant time to generate 8190-65534 Hosts Addresses `
    -ForegroundColor Yellow }
    $cntr = 0
    while($startInt -le $endInt){
        [Byte[]]$ipBytes = [System.BitConverter]::GetBytes($startInt)
        [Array]::Reverse($ipBytes)
        $IpAddresses[$cntr] = ([IpAddress]$ipBytes).IPAddressToString   
        $cntr++
        $startInt++
    }
    
    If($AddressesOnly){
        return $IpAddresses
    }
    Else{
        
        return [PSCustomObject]@{
            NetAddress = $netAddress.IPAddressToString
            BroadCast = $brodcastAddress.IPAddressToString
            CIDR = $Cidr
            NetMask = [IpAddress]$NetMask
            TotalHostAddresses = $hostAddresses
            AllNetworkAddresses = $IpAddresses
            }
    }

<#
.SYNOPSIS

Returns Data about IpAddresses and Ranges

.DESCRIPTION

Returns either an Array, Uint32, or PsCustomObject (dependent on Params)

.PARAMETER IpAddress
Specifies the IpAddress you want information about, this can be a network, broadcast, or host Address

.PARAMETER Cidr
Specifies the network size it is set to /24 i.e a class c

.PARAMETER ToNetMask
Returns the Netmask form of a cidr

.PARAMETER ToCidr
Returns the Cidr form of a NetMask

.PARAMETER ToDecimalValue
Switch that causes the Return to be the decimal value of the IpAddress

.PARAMETER AddressesOnly
Switch that causes an array of Addresses to be returned

.INPUTS

None. You cannot pipe objects to Get-netRange.

.OUTPUTS

returns PsCustomObject with NetAddress and BroadcastAddress Properties, can also return a String Array
of all IpAddress in the network range.  Finally it can return a Uint32 value of the IpAddress


.EXAMPLE

PS> Get-NetRange -IpAddress 192.168.1.0 -Cidr 24

NetAddress          : 192.168.1.0
BroadCast           : 192.168.1.255
CIDR                : 24
NetMask             : 255.255.255.0
TotalHostAddresses  : 254
AllNetworkAddresses : {192.168.1.0, 192.168.1.1, 192.168.1.2, 192.168.1.3...}

.EXAMPLE

PS> Get-NetRange -IpAddress 10.10.10.10 -ToDecimalValue
168430090

.EXAMPLE

PS> Get-NetRange -IpAddress 192.168.0.53 -Cidr 23 -AddressesOnly

192.168.1.0
192.168.1.1
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5
192.168.1.6
---Results Truncated---

#>

} 
