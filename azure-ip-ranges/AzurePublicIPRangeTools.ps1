Function Get-AzurePublicIPRangesXMLFile
{
<#
    .SYNOPSIS
        This function downloads the Azure IP ranges XML file to the current directory or a specified path.
    .DESCRIPTION
        This function downloads the Azure IP ranges XML file to the current directory or a specified path.
    .PARAMETER AzureIPRangeURL
        An optional parameter that is the URL to the Azure IP range XML file download page.
    .PARAMETER DestinationPath
        The locaiton on the local filesystem where the Azure IP range XML file is to be downloaded.
    .EXAMPLE
        Get-AzurePublicIPRangesXMLFile -DestinationPath C:\AzureIPXMLFiles\
        Get-AzurePublicIPRangesXMLFile -DestinationPath C:\AzureIPXMLFiles\ -AzureIPRangeURL 'https://www.microsoft.com/en-gb/download/confirmation.aspx?id=41653'
    .NOTES
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,HelpMessage='Enter the URL for the Azure IP range XML file')]
        [String]$AzureIPRangeURL = 'https://www.microsoft.com/en-gb/download/confirmation.aspx?id=41653',
    [Parameter(Mandatory=$true,HelpMessage='Enter the path where the XML file should be written')]
        [ValidateScript({ Test-Path $_ })]
        [String]$DestinationPath
)
    If( $null -eq $AzureIPRangeURL ) { $AzureIPRangeURL = 'https://www.microsoft.com/en-gb/download/confirmation.aspx?id=41653' }
    $AzureIPRangePage = (Invoke-WebRequest -Uri $AzureIPRangeURL )
    $AzureIPRangeXMLFileURL = ($AzureIPRangePage.Links |  Where-Object { $_.href -like "*PublicIP*xml" }).href

    Invoke-WebRequest -Uri $AzureIPRangeXMLFileURL -OutFile "$DestinationPath\AzurePublicIPRanges.xml"

}#EndFunction Get-AzureIPRangesXMLFile


Function Get-AzureRegionPublicIPAddressList
{
<#
    .SYNOPSIS
        The function lists the public IP addresses in a particular Azure region
    .DESCRIPTION
        The function lists the public IP addresses in a particular Azure region.
    .PARAMETER Region
        The Azure region for which you want to retrieve public IP addresses.
    .PARAMETER AzureIPRangeXMLFile
        The XML file containing the Azure IP ranges.
    .PARAMETER OutputAsNSGAllowRuleFormat
        This will result in the IP addresses to be output as outbound allow Network Security Group (NSG) rules in CSV form.
        Placeholder values will be used for the rule priority (RulePriority), subnet address prefix (SubnetAddressPrefix).
        For each IP address/range two rules will be listed one for HTTP and another for HTTPS.
    .EXAMPLE
        Get-AzureRegionPublicIPAddressList -Region 'europenorth' -AzureIPRangeXMLFile C:\AzurePublicIPs.xml
        Get-AzureRegionPublicIPAddressList -Region 'europenorth' -AzureIPRangeXMLFile C:\AzurePublicIPs.xml -OutputAsNSGAllowRuleFormat
#>
 [CmdletBinding()]
 Param(
    [Parameter(Mandatory=$true,HelpMessage='Enter the region.')]
    [String]$Region,
    [Parameter(Mandatory=$true,HelpMessage='Enter the path to the Azure IP ranges XML file.')]
    [String]$AzureIPRangeXMLFile,
    [Parameter(ParameterSetName='NSGFormat',Mandatory=$false,HelpMessage='This switch causes the IP addresses to be listed as allow NSG rules.')]
    [Switch]$OutputAsNSGAllowRuleFormat,    
    [Parameter(ParameterSetName='NSGFormat',Mandatory=$true,HelpMessage='This switch causes the IP addresses to be listed as allow NSG rules.')]
    [String]$NSGRuleNamePrefix = 'Allow-AzurePlatformIP-',
    [Parameter(ParameterSetName='IPSecurityFormat',Mandatory=$false,HelpMessage='This switch causes the IP addresses to be listed as allow IIS Ip Security rules XML.')]
    [Switch]$OutputAsIisIpSecurityXMLFormat
 )

$IpSecuirtyXml = [xml] @'
<system.webServer>
    <security>
    <!--Unlisted IP addresses are denied access-->
    <ipSecurity allowUnlisted="false">
        <!--The following IP addresses are granted access-->
        <add allowed="true" ipAddress="0.0.0.0" subnetMask="255.255.255.255" />
    </ipSecurity>
    </security>
</system.webServer>
'@

$IpSecuirtyXml.'system.webServer'.security.ipSecurity.InnerXml = $null 

    If( $OutputAsNSGAllowRuleFormat )
    {
        Write-Output "RuleName,Priority,Action,Direction,SourceAddressPrefix,SourcePortRange,DestinationAddressPrefix,DestinationPortRange,Protocol,Description"
    }

    $AzureIPRanges = [xml] (Get-Content $AzureIPRangeXMLFile)
    #Check that the supplied region matches one in the file
    If( $AzureIPRanges.AzurePublicIpAddresses.Region.Name -contains $Region)
    {
        $AzureIPRanges.AzurePublicIpAddresses.Region | ForEach-Object {
            If($_.Name -eq $Region )
            {
                $RuleNumber = 1;
                ForEach( $IPAddress in $_.IpRange )
                {                                                                                  
                    If( $OutputAsNSGAllowRuleFormat )
                    {
                        Write-Output "$($NSGRuleNamePrefix)-HTTPS-$RuleNumber-Outbound,RulePriority,Allow,Outbound,SubnetAddressPrefix,*,$($IpAddress.Subnet),443,TCP,Allow Azure VM Agent and Extension HTTPS traffic"
                        $RuleNumber++
                        Write-Output "$($NSGRuleNamePrefix)-HTTP-$RuleNumber-Outbound,RulePriority,Allow,Outbound,SubnetAddressPrefix,*,$($IpAddress.Subnet),80,TCP,Allow Azure VM Agent and Extension HTTP traffic"
                        $RuleNumber++
                    }
                    ElseIf( $OutputAsIisIpSecurityXMLFormat )
                    {
                        $IPAddress = ($IPAddress.Subnet -split '/')[0]
                        $MaskLength = ($IPAddress.Subnet -split '/')[1]
                        [IPAddress] $ip = 0
                        $ip.Address = ([UInt32]::MaxValue -1) -shl (32 - $MaskLength) -shr (32 - $MaskLength)                        
                        $xmlElt = $IpSecuirtyXml.CreateElement("add")
                        $xmlAtt = $IpSecuirtyXml.CreateAttribute("ipAddress")
                        $xmlAtt.Value = $IPAddress.toString()
                        [void] $xmlElt.Attributes.Append($xmlAtt)
                        $xmlAtt = $IpSecuirtyXml.CreateAttribute("subnetMask")
                        $xmlAtt.Value =  $ip.IPAddressToString.toString()
                        [void] $xmlElt.Attributes.Append($xmlAtt)
                        [void] $IpSecuirtyXml.'system.webServer'.security.ipSecurity.AppendChild($xmlElt)
                    }
                    Else
                    {
                        $IPAddress
                    }
                }
            }        
        }
    }
    Else
    {
        Throw "The supplied region $Region is not in the list of regions in the Azure IP Range XML file ($($AzIPs.AzurePublicIpAddresses.Region.Name -join ","))"
    }

    If( $OutputAsIisIpSecurityXMLFormat )
    {
      return $IpSecuirtyXml.OuterXml
    }
}#EndFunction Get-AzureRegionPublicIPAddressList


Function Get-AzurePubicIpXMLRegionList
{
<#
    .SYNOPSIS
        The function takes the Azure Public IP address XML file and returns an array of region names
    .DESCRIPTION
        The function takes the Azure Public IP address XML file and returns an array of region names
    .PARAMETER AzureIPRangeXMLFile
        The XML file containing the Azure IP ranges.
    .EXAMPLE
        Get-AzureRegionPublicIPAddressList -AzureIPRangeXMLFile C:\AzurePublicIPs.xml
#>
 [CmdletBinding()]
 [OutputType([object[]])]
 Param(
    [Parameter(Mandatory=$true,HelpMessage='Enter the path to the Azure IP ranges XML file.')]
    [String]$AzureIPRangeXMLFile
)
    $AzureIPRanges = [xml] (Get-Content $AzureIPRangeXMLFile)    
    return $AzureIPRanges.AzurePublicIpAddresses.Region.Name
}#EndFuncion Function Get-AzurePubicIpXMLRegionList


Function Test-IPIsInNetwork
{
<#
    .SYNOPSIS
        This function checks if an IP address falls within a particular IP range
    .DESCRIPTION
        This function checks if an IP address falls within a particular IP range (in CIDR format)
    .PARAMETER IpAddress
        The IP Address
    .PARAMETER IpRangeInCidrFormat
        The IP Address range specified in CIDR format e.g. 192.168.0.0/24
    .PARAMETER
        Test-IPIsInNetwork -IpAddress ‘192.168.250.10’ -IpRangeInCidrFormat ‘192.168.240.0/20’ 

    .EXAMPLE
#>
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param(
        [Parameter(Mandatory=$true,HelpMessage='Enter the IP address')]
            [string] $IpAddress,
        [Parameter(Mandatory=$true,HelpMessage='The IP range in cidr format')]
            [string] $IpRangeInCidrFormat
    )

    $network, [int]$subnetlen = $IpRangeInCidrFormat.Split('/')
    $a = [uint32[]]$network.split('.')
    [uint32] $unetwork = ($a[0] -shl 24) + ($a[1] -shl 16) + ($a[2] -shl 8) + $a[3]

    $mask = (-bnot [uint32]0) -shl (32 - $subnetlen)

    $a = [uint32[]]$IpAddress.split('.')
    [uint32] $uip = ($a[0] -shl 24) + ($a[1] -shl 16) + ($a[2] -shl 8) + $a[3]

    $unetwork -eq ($mask -band $uip)
}#EndFunction Test-IPIsInNetwork


Function Test-IPIsInAzureRegion
{
 [CmdletBinding()]
 Param(
    [Parameter(Mandatory=$true,HelpMessage='Enter the region.')]
    [String]$Region,
    [Parameter(Mandatory=$true,HelpMessage='Enter the path to the Azure IP ranges XML file.')]
    [String]$AzureIPRangeXMLFile,
    [Parameter(Mandatory=$true,HelpMessage='Enter the IP address')]
    [string] $IpAddress 
)
    $IpIsInRegion = $false
    $AzureIPRanges = [xml] (Get-Content $AzureIPRangeXMLFile)
    #Check that the supplied region matches one in the file
    If( $AzureIPRanges.AzurePublicIpAddresses.Region.Name -contains $Region)
    {
        $AzureIPRanges.AzurePublicIpAddresses.Region | ForEach-Object {
            If($_.Name -eq $Region )
            {
                $RuleNumber = 1;
                ForEach( $IPAddressRange in $_.IpRange )
                {
                    If( (Test-IPIsInNetwork -IpAddress $IpAddress -IpRangeInCidrFormat $IPAddressRange.Subnet) -eq $true )
                    {
                        $IpIsInRegion = $true
                        break;
                    }
                }
            }
        }
    }
    return $IpIsInRegion
}#Function Test-IPIsInAzureRegion

Export-ModuleMember -Function Get-*