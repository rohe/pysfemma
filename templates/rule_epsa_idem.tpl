@RuleName = "eduPersonScopedAffiliation attribute from LDAP"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://unibo/idem/epsaLdap"), query = ";extensionAttribute5;{0}", param = c.Value);

@RuleName = "eduPersonScopedAffiliation member"
c:[Type == "http://unibo/idem/epsaLdap", Value =~ ".*member.*"] => issue(Type = "urn:mace:dir:attribute-def:eduPersonScopedAffiliation", Value = "member@unibo.it", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

@RuleName = "eduPersonScopedAffiliation staff"
c:[Type == "http://unibo/idem/epsaLdap", Value =~ ".*staff.*"] => issue(Type = "urn:mace:dir:attribute-def:eduPersonScopedAffiliation", Value = "staff@unibo.it", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

@RuleName = "eduPersonScopedAffiliation student"
c:[Type == "http://unibo/idem/epsaLdap", Value =~ ".*student.*"] => issue(Type = "urn:mace:dir:attribute-def:eduPersonScopedAffiliation", Value = "student@unibo.it", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

@RuleName = "eduPersonScopedAffiliation affiliate"
c:[Type == "http://unibo/idem/epsaLdap", Value =~ ".*affiliate.*"] => issue(Type = "urn:mace:dir:attribute-def:eduPersonScopedAffiliation", Value = "affiliate@unibo.it", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");

@RuleName = "eduPersonScopedAffiliation alum"
c:[Type == "http://unibo/idem/epsaLdap", Value =~ ".*alum.*"] => issue(Type = "urn:mace:dir:attribute-def:eduPersonScopedAffiliation", Value = "alum@unibo.it", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");