Add-ADFSRelyingPartyTrust -Name "($fedName) $rpName" -MetadataFile "$metadataFile"
Set-ADFSRelyingPartyTrust -TargetName "($fedName) $rpName" -IssuanceTransformRulesFile "$rulesetFile" -SignatureAlgorithm http://www.w3.org/2000/09/xmldsig#rsa-sha1 -IssuanceAuthorizationRules '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true"); '

