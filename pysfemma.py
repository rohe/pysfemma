#!/usr/bin/env python
#
# Name: PySAML2 based FEderation Metadata Manager for ADFS (pysFEMMA)
# Version: 0.1
# Author: Roland Hedberg <roland.hedberg@umu.se>
#
# Heavily based on
# Name: FEderation Metadata Manager for ADFS (FEMMA)
# Version: 0.4
# Author: Cristian Mezzetti <cristian.mezzetti@unibo.it>
# Home-page: http://sourceforge.net/projects/femma
# License: GNU GPL v2
# Description: This script parses a (Shibboleth) federation 
#              metadata XML content and creates a pool of 
#              metadata files and a powershell script in order
#              to automatically configure and update an Active
#              Directory Federation Services STS (Security Token Service).
#
# Copyright (C) 2010  Cristian Mezzetti
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.


import os
import shutil
import sys
import ConfigParser
import argparse

from os.path import join as pjoin
from saml2.assertion import Policy
from saml2.attribute_converter import ac_factory
from saml2.md import AssertionConsumerService
from saml2.md import SingleLogoutService
from saml2.mdie import from_dict

from saml2.mdstore import MetadataStore
from string import Template
from saml2.sigver import split_len, active_cert

import xmldsig
import xmlenc
from saml2 import md
from saml2 import config
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_SOAP
from saml2 import BINDING_PAOS
from saml2 import saml
from saml2.extension import dri
from saml2.extension import idpdisc
from saml2.extension import mdattr
from saml2.extension import mdrpi
from saml2.extension import mdui
from saml2.extension import shibmd
from saml2.extension import ui

ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc,
    mdrpi.NAMESPACE: mdrpi,
    shibmd.NAMESPACE: shibmd
}

ATTRCONV = ac_factory("./attributemaps")


ENTITY_ATTRIBUTES = 'urn:oasis:names:tc:SAML:metadata:attribute&EntityAttributes'
ENTITY_CATEGORY = 'http://macedir.org/entity-category'


# -----------------------------------------------------------------------------

BINDINGS_NOT_SUPPORTED = [
    BINDING_HTTP_ARTIFACT, BINDING_SOAP, BINDING_PAOS,
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign',
    'urn:oasis:names:tc:SAML:1.0:profiles:browser-post',
    'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01'
]

SEVICES_NOT_SUPPORTED = [
    AssertionConsumerService, SingleLogoutService
]

DIR = {"metadata": "entities-temp", "ruleset": "ruleset-temp",
       "template": "templates"}
TPL = ["ruleset_persistent", "ruleset_transient",
       "powershell_metadata_update", "powershell_base"]


class Femma(object):
    def __init__(self, mds, settings_file="settings.cfg"):
        self.mds = mds
        self.settings_file = settings_file
        self.policy = None
        self.template_dir = ""
        self.metadata_dir = ""
        self.ruleset_dir = ""
        
        self.idp_entity_id = ""
        self.sp_entity_id = ""
        self.my_claim_type = ""
        self.fed_name_prefix = ""
        self.my_proxy = ""
        self.ps1_filename = ""
        self.ruleset_transient = ""
        self.ruleset_persistent = ""
        self.powershell_base = ""
        self.powershell_metadata_update = ""
        self.config = None

    def setup(self):
        for name, filename in DIR.items():
            setattr(self, name + "_dir", pjoin(os.getcwd(), filename))
        for template in TPL:
            setattr(self, template, pjoin(self.template_dir, template + ".tpl"))
        self.rule_prefix = "rule_"
        self.rules_dir = self.template_dir
        self.custom_rules_dir = pjoin(self.template_dir, "customRules")
        self.ps1_filename = pjoin(os.getcwd(), "update_adfs_rptrust.ps1")
        
        if os.path.exists(self.settings_file):
            self.config = ConfigParser.ConfigParser()
            self.config.read(self.settings_file)
            self.idp_entity_id = self.config.get('Settings', "idpEntityID")
            self.sp_entity_id = self.config.get('Settings', "spEntityID")
            self.my_claim_type = self.config.get('Settings', "myClaimType")
            self.fed_name_prefix = self.config.get('Settings', "fedNamePrefix")
            
            self.my_proxy = self.config.get('Settings', "myProxy")
            if self.my_proxy.__len__() > 0:
                self.my_proxy = self.my_proxy + ":" + self.config.get(
                    'Settings', "myProxyPort")

            try:
                ent_cats = self.config.get("Settings",
                                           "entityCategories").split(",")
            except ConfigParser.NoOptionError:
                pass
            else:
                self.policy = Policy({"default": {
                    "entity_categories": ent_cats}})

            if not (os.path.exists(self.metadata_dir) and 
                    os.path.isdir(self.metadata_dir)):
                os.mkdir(self.metadata_dir)
            if not (os.path.exists(self.ruleset_dir) and 
                    os.path.isdir(self.ruleset_dir)):
                os.mkdir(self.ruleset_dir)
        else:
            print "ERROR: FEMMA configuration files not found"
            sys.exit(1)
    
    def clean_up(self):
        """
        Cleans up temporary folders
        """
        shutil.rmtree(self.metadata_dir, True)
        shutil.rmtree(self.ruleset_dir, True)

        try:
            os.unlink(self.ps1_filename)
        except os.error:
            pass

        sys.exit(0)

    def entity_to_ignore(self,entityID):
        """
        Checks if the provided entityID of the Service Provider is blacklisted
        To blacklist an entity ID insert a section into the settings file, with
        similar syntax:
        [ExcludeEntityID]
        entity1 = "https://my.example.com/service"
        entity2 = "https://anotherexample.net/service2"
        """

        try:
            toIgnore = self.config.items('ExcludeEntityID')
        except ConfigParser.NoSectionError:
            return False

        if entityID in [x[1] for x in toIgnore]:
            return True
        else:
            return False

    def _strip_protocol_identifier(self, eid):
        if eid.startswith("http"):
            return eid.split('://')[1]
        else:
            return eid

    def is_persistent(self, entityID):
        """
        Checks if the provided entityID of the Service Provider has configured rules
        that match a list of sensitive ones. If this is the case, it associates a
        persistent-id.
        Default is transient-id.
        To customize this behavior, use the following section and syntax in
        settings.cfg:
        [SensitiveAttributes]
        rules = rule1,rule2

        To force the persistent NameID format, specify "persistent" in the SP
        attribute list
        """
        ret = False

        entityName = self._strip_protocol_identifier(entityID)

        try:
            sensitiveRules = self.config.get('SensitiveAttributes', 'rules')
            configuredRules = self.config.get('ServiceProviderAttributes',
                                              entityName)
            for r in sensitiveRules.split(','):
                if r in configuredRules.split(','):
                    ret = True
                    break
        except Exception, e:
            pass

        return ret

    def _entity_category_attributes(self, entity, extensions):
        attrs = []
        try:
            ext_elem = extensions["extension_elements"]
        except KeyError:
            pass
        else:
            for ext_elem in ext_elem:
                if ext_elem["__class__"] == ENTITY_ATTRIBUTES:
                    for attr in ext_elem["attribute"]:
                        if attr["name"] == ENTITY_CATEGORY:
                            for val in attr["attribute_value"]:
                                attrs.extend(
                                    self.policy.entity_category_attributes(
                                        val["text"]))
        if attrs:
            attrs.extend(self.policy.entity_category_attributes(""))
            # get rid of duplicates
            list(set(attrs))

        return attrs

    def _rules(self, rules):
        ret = ""
        for r in rules:
            r = r.lower()
            ruleFileName = self.rule_prefix + r + '.tpl'
            if os.path.exists(self.rules_dir + os.sep + ruleFileName):
                ruleFile = open(self.rules_dir + os.sep + ruleFileName, 'r')
                ret += ruleFile.read()
                ruleFile.close()
            else:
                names = self.config.get('Attributes', r).split(",")
                try:
                    attribute_name, name = names
                except ValueError:
                    attribute_name = name = names[0]
                fname = pjoin(self.rules_dir, self.rule_prefix + '.tpl')
                ruleTPL = Template(open(fname, "r").read())
                rule_set = ruleTPL.substitute(attribute=attribute_name,
                                              name=name)
                ret += rule_set
        return ret

    def get_rules(self, entity):
        """
        Checks if the provided entityID of the Service Provider needs additional
        rules other than the default ones.
        Every name in the list identifies a rule template
        (i.e.: eppn => rule_eppn.tpl).
        The entity ID name must be stripped of the protocol prefix (http://,
        https://)
        Example configuration settings:
        [ServiceProviderAttributes]
        my.example.com/service=eppn,o,ou
        anotherexample.net/service2=carLicense

        Entity category specification are used if no configuration settings are
        found for a entity_id.

        :param entity: Entity Descriptor
        :return: rules
        """
        ret = ""

        entityName = self._strip_protocol_identifier(entity["entity_id"])

        try:
            rules = self.config.get('ServiceProviderAttributes', entityName)
        except ConfigParser.NoSectionError:
            try:
                extensions = entity["extensions"]
            except KeyError:
                pass
            else:
                ret = self._rules(
                    self._entity_category_attributes(entity, extensions))
        else:
            ret = self._rules(rules.split(','))

        if not ret and self.policy:
            ret = self._rules(self.policy.entity_category_attributes(""))

        return ret

    def ruleset_creation(self, myClaimType, rulesetFileName, entity):
        """
        Creates Service Provider ruleset file with NameID creation based on
        persistent-id by default
        """
        _eid = entity["entity_id"]
        try:
            # load template from configured file
            if self.is_persistent(_eid):
                ruleID = Template(open(self.ruleset_persistent, "r").read())
            else:
                ruleID = Template(open(self.ruleset_transient, "r").read())

            # susbstitutes rules and entityID
            outRuleset = ruleID.substitute(claimBaseType=myClaimType,
                                           spNameQualifier=_eid,
                                           nameQualifier=self.idp_entity_id)
            # create ruleset files
            rulesetFile = open(rulesetFileName, "w")
            rulesetFile.write(outRuleset)
            rulesetFile.write(self.get_rules(entity))
            rulesetFile.close()
        except Exception, e:
            print(e)
        return

    def stripBindingsNotSupported(self, entity):
        """
        Removes AssertionConsumerServices and SingleLogoutServices that uses
        bindings that ADFS does not support.
        Also removes AssertionConsumerServices endpoint that doesn't use HTTPS.
        Returns the modified entity or None if there are not remaining endpoints
        after filtering.

        :param entity: Entity Descriptor
        :return: Entity descriptor or None of no usable endpoints remained
        """

        _sps = []
        for sp in entity["spsso_descriptor"]:
            _acs = []
            for acs in sp["assertion_consumer_service"]:
                if acs["binding"] not in BINDINGS_NOT_SUPPORTED:
                    if acs["location"].startswith("https:"):
                        _acs.append(acs)
            _sls = []
            try:
                _slss = sp["single_logout_service"]
            except KeyError:
                pass
            else:
                for sls in _slss:
                    if sls["binding"] in BINDINGS_NOT_SUPPORTED:
                        print "Removed not supported binding: %s" % sls["binding"]
                        continue
                    else:
                        if sls["location"].startswith("https:"):
                            _sls.append(sls)
                        else:
                            print "Removed endpoint since not HTTPS"
                            continue

            if not _acs:
                continue
            else:
                sp["assertion_consumer_service"] = _acs
                sp["single_logout_service"] = _sls
                _sps.append(sp)

        if not _sps:
            return None
        else:
            entity["spsso_descriptor"] = _sps
            return entity

    def stripRolloverKeys(self, entity):
        """
        If the entity metadata contains keys for safe-rollover, strips the
        Standby key because ADFS can't handle it

        :param entity: Entity descriptor
        :return: Entity descriptor or None of no working keys remain
        """
        _sps = []
        for sp in entity["spsso_descriptor"]:
            toRemove = []
            try:
                key_desc = sp["key_descriptor"]
            except KeyError:
                continue
            else:
                for kd in key_desc:
                    try:
                        key_name = kd["key_info"]["key_name"]
                    except KeyError:
                        pass
                    else:
                        stand_by = False
                        for kn in key_name:
                            if kn["text"] == "Standby":
                                toRemove.append(kd)
                                break
                        if stand_by:
                            break
                    x509_data = kd["key_info"]["x509_data"]
                    cert_to_remove = []
                    for x in x509_data:
                        xc = x["x509_certificate"]
                        cert = xc["text"].strip()
                        cert = "\n".join(split_len("".join([s.strip() for s in
                                                            cert.split()]), 64))
                        if not active_cert(cert):
                            cert_to_remove.append(x)
                    for c in cert_to_remove:
                        x509_data.remove(c)
                    if not kd["key_info"]["x509_data"]:
                        toRemove.append(kd)

            for j in toRemove:
                sp["key_descriptor"].remove(j)
                print ("WARNING: removed KeyName element")

            if sp["key_descriptor"]:
                _sps.append(sp)

        if not _sps:
            return None
        else:
            entity["spsso_descriptor"] = _sps
            return entity

    def extract(self):
        """
        Creates separate metadata file for each Service Provider entityID in
        the original metadata files.

        It will weed out SPs that fulfills any of these criteria:
        1. no valid keys
        2. no Assertion Consuming Services endpoints with bindings supported by
            ADFS
        3. no HTTPS based Assertion Consuming Service endpoints
        """
        pshScript = ""
        pshScriptTemplate = Template(open(self.powershell_metadata_update,
                                          'r').read())

        # for EntityDescriptor extracts SP and write a single metadata file
        for eid, entity in self.mds.items():
            if "spsso_descriptor" in entity:
                if not self.entity_to_ignore(eid):
                    print "---- %s ----" % eid
                    entity = self.stripRolloverKeys(entity)
                    if not entity:
                        print "No working keys for %s" % eid
                        continue
                    entity = self.stripBindingsNotSupported(entity)
                    if not entity:
                        print "No working endpoints for %s" % eid
                        continue

                    fname = eid.replace('/', '_').replace('.', '_').replace(
                        ':', '_')
                    fname = "".join(
                        [x for x in fname
                         if x.isalpha() or x.isdigit() or x == '-' or x == '_'])

                    print " ".join(["Generating XML metadata for", eid])
                    entityFileName = pjoin(self.metadata_dir,
                                           fname + ".xml")
                    entityFile = open(entityFileName, "w")
                    entityFile.write("%s" % from_dict(entity, ONTS))
                    entityFile.close()
                    rulesetFileName = pjoin(self.ruleset_dir, fname)
                    self.ruleset_creation(self.my_claim_type,
                                          rulesetFileName, entity)
                    pshScript += pshScriptTemplate.substitute(
                        fedName=self.fed_name_prefix,
                        metadataFile=entityFileName,
                        rpName=eid,
                        rulesetFile=rulesetFileName)

        if pshScript:
            print "Generating powershell script for Relying Party configuration update..."
            pshScriptBaseTemplate = Template(open(self.powershell_base,
                                                  'r').read())
            pshScript = pshScriptBaseTemplate.substitute(
                fedName=self.fed_name_prefix) + pshScript
            pshScriptFile = open('update_adfs_rptrust.ps1', 'w')
            pshScriptFile.write(pshScript)
            pshScriptFile.close()


if __name__ == "__main__":
    _parser = argparse.ArgumentParser()
    _parser.add_argument('-u', dest='url', nargs="?",
                         help='URL of federation metadata')
    _parser.add_argument('-f', dest='filename', nargs="?",
                         help='filename of federation metadata')
    _parser.add_argument(
        '-x', dest='xmlsec', nargs=1,
        help='path to xmlsec binary for signature verification')
    _parser.add_argument(
        '-c', dest='cert', nargs="?", default="",
        help='certificate for signature verification')
    _parser.add_argument(
        '-C', dest='clear', action='store_true', help='clean up')

    args = _parser.parse_args()

    if args.clear:
        fem = Femma(None)
        fem.setup()
        fem.clean_up()
    else:
        sec_config = config.Config()
        sec_config.xmlsec_binary = args.xmlsec[0]
        mds = MetadataStore(ONTS.values(), ATTRCONV, sec_config,
                            disable_ssl_certificate_validation=True)
        if args.url:
            mds.load("remote", url=args.url, cert=args.cert)
        if args.filename:
            if args.cert:
                mds.load("local", args.filename, cert=args.cert)
            else:
                mds.load("local", args.filename)


        fem = Femma(mds)
        fem.setup()
        fem.extract()
