Add-PSSnapin Microsoft.Adfs.PowerShell
$$stsproperties = Get-ADFSSyncProperties
if (-not ($$stsproperties.role -eq "PrimaryComputer")) { exit }
Get-ADFSRelyingPartyTrust | Where-Object {$$_.Name -like "($fedName)*"} | ForEach-Object {Remove-ADFSRelyingPartyTrust -TargetName $$_.Name}
