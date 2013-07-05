@RuleName = "cn"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] => add(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/cn"), query = ";cn;{0}", param = c.Value);

@RuleName = "urn:mace:dir:attribute-def:cn"
c1:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenName"] && c2:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"] => issue(Type = "urn:mace:dir:attribute-def:cn", Value = c1.Value + " " + c2.Value, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
