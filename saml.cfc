component output="false" mixin="controller,model" {
    function init(){
        this.version="2.0,2.0.1";
        return this;
    }

    /**
	*
	* Handles creating a saml_sp_metadata.xml for first time IDP configuration
	*
	* [section: Plugins]
	* [category: SAML]
	*
	* @issuer the name (or url) of the application
    * @consumer the Attribute Consume Service Endpoint (for HTTP-POST)
    * @singleSignOutService Single Logout Service Endpoint (HTTP-REDIRECT)
    * @cert (self-signed) X.509 certificate if the request has to be signed
    * @fileLocation the location of the generated file (by default, the cfwheels "files" directory)
	*/
    public function buildSPMeta(required string issuer, required string consumer, string singleSignOutService, string cert, string fileLocation="files") {
        try{
            var spMetaXML = "";
            // create directory if not exists
            if (!directoryExists(ExpandPath(arguments.fileLocation))) directoryCreate(ExpandPath(arguments.fileLocation))
            
            var spMetaFile = ExpandPath(arguments.fileLocation & "/" & "saml_sp_metadata.xml");

            savecontent variable="spMetaXML" {
                writeOutput('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>');
                writeOutput('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#arguments.issuer#">')
                writeOutput('<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">')
                if (len(arguments.cert)) {
                    writeOutput('<md:KeyDescriptor use="signing">')
                    writeOutput('<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig##">')
                    writeOutput('<ds:X509Data>')
                    writeOutput('<ds:X509Certificate>#arguments.cert#</ds:X509Certificate>')
                    writeOutput('</ds:X509Data>')
                    writeOutput('</ds:KeyInfo>')
                    writeOutput('</md:KeyDescriptor>')
                    writeOutput('<md:KeyDescriptor use="encryption">')
                    writeOutput('<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig##">')
                    writeOutput('<ds:X509Data>')
                    writeOutput('<ds:X509Certificate>#arguments.cert#</ds:X509Certificate>')
                    writeOutput('</ds:X509Data>')
                    writeOutput('</ds:KeyInfo>')
                    writeOutput('</md:KeyDescriptor>')
                }
                if (len(arguments.singleSignOutService)) {
                    writeOutput('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#arguments.singleSignOutService#"/>')
                }
                writeOutput('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>')
                writeOutput('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#arguments.consumer#" index="1"/>')
                writeOutput('</md:SPSSODescriptor>')
                writeOutput('</md:EntityDescriptor>')        
            }

            FileWrite(spMetaFile, spMetaXML);

        }catch (Any e) { dump(e); abort; }

    }

    /**
	*
	* Create a valid SAML AuthNRequest (for HTTP-POST binding)
	*
	* [section: Plugins]
	* [category: SAML]
	*
	* @issuer                   the name (or url) of the application
    * @consumer                 the Attribute Consume Service Endpoint (for HTTP-POST)
    * @idpSingleSignOnService   location of the single sign-on service of the IDP   
	* @asString     
	*/
    public string function buildAuthNRequest(required string issuer, required string consumer, required string idpSingleSignOnService, boolean asString = false){
        try{
            var reqTS = DateFormat(Now(), "yyyy-mm-dd") & 'T' & TimeFormat(Now(), "HH:nn:ss") & '.343Z';
            var reqID = "lucee-" & createUUID();
            var authnXML = "";

            savecontent variable="authnXML" {
                WriteOutput('<?xml version="1.0" encoding="UTF-8"?>');
                WriteOutput('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ');
                    WriteOutput('AssertionConsumerServiceURL="#arguments.consumer#" ');
                    WriteOutput('Destination="#arguments.idpSingleSignOnService#" ');
                    WriteOutput('ID="#reqID#" ');
                    WriteOutput('IssueInstant="#reqTS#" ');
                    WriteOutput('ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">');
                WriteOutput('<samlp:Issuer xmlns:samlp="urn:oasis:names:tc:SAML:2.0:assertion">#arguments.issuer#</samlp:Issuer>');
                WriteOutput('<saml2p:NameIDPolicy xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>');
                WriteOutput('</samlp:AuthnRequest>');
            }

            if (!arguments.asString) {
                authnXML = ToBase64(authnXML);
            }

        }catch (Any e) { 
            authnXML = "ERROR: Unable to create AuthN."; 
        }

        return authnXML;
    }


    /**
	*
	* Handles validating the saml response from the IDP and returns struct with data provided from the IDP
	*
	* [section: Plugins]
	* [category: SAML]
	*
	* @response    
    * @verbose     
	*/
    public struct function processResponse(required string response, boolean verbose = false){
        var sigValid = false;
        var respXML = "";
        var passError = "";
        // Build Return Struct
        var rtnStruct = {};
            rtnStruct.request = {};
            rtnStruct.request.failReason = "";
            rtnStruct.request.processStack = [];
        try{
            respXML ="";
            try {
                respXML = XmlParse(ToString(ToBinary(arguments.response)));
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Base64");}
            }catch (Any e) { }
            if(not isXML(respXML)) {
                try {
                    respXML = XmlParse(ToString(ToBinary(arguments.response)));
                    if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Url Encoded Base64");}
                }catch (Any e) { }
            }

            if(not isXML(respXML)) {
                try {
                    var b64decoder = CreateObject("Java", "org.apache.commons.codec.binary.Base64");
                    var decoded = b64decoder.decode(arguments.response);
                    var respXML = XmlParse(createObject("java","java.lang.String").init(decoded));
                    if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Converted from Java Base64 Decoder");}
                }catch (Any e) { if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Response Not Base64"); } }
            }

            var doc = respXML.getDocumentElement();
            // Resolve ID issues with DOM3
            var idResolver = CreateObject("Java", "org.apache.xml.security.utils.IdResolver");
            var assertionElement = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
            var attrStore = assertionElement.getAttributes();
            
            var idAttr = CreateObject("Java","org.w3c.dom.Attr");
            var idAttr = attrStore.getNamedItem("ID");
           
            idResolver.registerElementById(assertionElement, idAttr);
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"DOM Processed");}
            
            var SecInit = CreateObject("Java", "org.apache.xml.security.Init").Init().init();
            var SignatureConstants=CreateObject("Java", "org.apache.xml.security.utils.Constants");
            var SignatureSpecNS = SignatureConstants.SignatureSpecNS;
            var xmlSignatureClass = CreateObject("Java", "org.apache.xml.security.signature.XMLSignature");
            
            var xmlSignature = xmlSignatureClass.init(doc.getElementsByTagNameNS(SignatureSpecNS,"Signature").item(0),javacast("string",""));
            var keyInfo = xmlSignature.getKeyInfo();
            var X509CertificateResolverCN = "org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver";
            var keyResolver=CreateObject("Java", X509CertificateResolverCN).init();
            keyInfo.registerInternalKeyResolver(keyResolver);
            var x509cert = keyInfo.getX509Certificate();
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Signature Object Staged"); }

            // Is the Sig Valid?
            var sigValid = xmlSignature.checkSignatureValue(x509cert);
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Signature Checked"); }

            //Extract conditions
            var conditionElement = doc.getElementsByTagName("saml2:Conditions").item(0);
            
            var conditions = conditionElement.getAttributes();
            var condBefore = conditions.getNamedItem("NotBefore").getNodeValue();
            var condAfter = conditions.getNamedItem("NotOnOrAfter").getNodeValue();
            if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Conditions Staged"); }

            var requestTS = DateAdd("s", 2, Now());

            if (YesNoFormat(sigValid)) {
                rtnStruct.authvalid = true;
                if (DateCompare(requestTS, DateConvertISO8601(condBefore),"s") < 0) {
                    rtnStruct.authvalid = false;
                    rtnStruct.request.failReason = "Not Before";
                    if (arguments.verbose) {
                        rtnStruct.request.error = "Authentication must not be before " & DateConvertISO8601(condBefore) & ". Request made on " & requestTS & ".";
                    }
                } else if (false && DateCompare(requestTS, DateConvertISO8601(condAfter),"s") >= 0) {
                    rtnStruct.authvalid = false;
                    rtnStruct.request.failreason = "Not On or After";
                    if (arguments.verbose) {
                        rtnStruct.request.error = "Authentication must not be on or after " & DateConvertISO8601(condAfter) & ". Request made on " & requestTS & ".";
                    }
                }
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"Conditions Tested"); }
            } else {
                rtnStruct.authvalid = false;
                rtnStruct.request.valid = false;
                rtnStruct.request.failReason = "Invalid Signature";
            }
            if (arguments.verbose) {
                rtnStruct.request.certExpire = x509cert.getNotAfter();
                rtnStruct.request.testNotbefore = DateConvertISO8601(condBefore) & " (" & DateCompare(requestTS, DateConvertISO8601(condBefore),"s") & ")";
                rtnStruct.request.testOnorafter = DateConvertISO8601(condAfter) & " (" & DateCompare(requestTS, DateConvertISO8601(condAfter),"s") & ")";
                rtnStruct.request.testAuth = requestTS;
                rtnStruct.request.testSig = sigValid;
            }

            // Extract User
            var userStruct = {};

            if (YesNoFormat(sigValid) or arguments.verbose) {
                var userNode = xmlSearch(respXML, "//*[local-name()='AttributeStatement']");
                for (usr=1;usr LTE ArrayLen(userNode[1].XmlChildren);usr=usr+1) {
                    name = userNode[1].XmlChildren[usr].XmlAttributes.Name;
                    var valArray = [];
                    var usrval=1;
                    for (usrval=1;usrval LTE ArrayLen(userNode[1].XmlChildren[usr].XmlChildren);usrval=usrval+1) {
                        valArray[usrval] = userNode[1].XmlChildren[usr].XmlChildren[usrval].XmlText;
                    }
                    userStruct[name] = valArray;
                    // Places AccountName into the better named racf entry in the array. May need to adjust based on your applications attributes.
                    // Alternatively you can grab from NameID in the Saml Reponse, but it is not in the AttributeStatement so this loop will not see it.
                    if (name contains "samaccountname") {
                        userStruct["racf"] = valArray;
                    }
                }
                rtnStruct.user = userStruct;
                if (arguments.verbose) { pStack = ArrayAppend(rtnStruct.request.processStack,"User Information Extracted"); }
            }

        }catch (Any e) {
            rtnStruct.authvalid = false;
            rtnStruct.request.failReason = "Core Failure";
				writeLog(type="Error", file="exception", text="Error Decoding SAML Response: #serializeJSON(e.stacktrace)#");
            if (arguments.verbose and structKeyExists(e, "message")) {
                rtnStruct.request.error = e.message;
            }
        }

        return rtnStruct;
    }
    
    public function DateConvertISO8601(required string ISO8601dateString, numeric inZoneOffset = 0) {
        var targetZoneOffset = arguments.inZoneOffset;
        if (targetZoneOffset eq 0) {
            // Eastern Standard Time Offset
            targetZoneOffset = -5;
            // Get Server Timezon Info
            var TimeZoneInfo = GetTimeZoneInfo();
            // If Daylight Savings Time
            if ( TimeZoneInfo.isDSTOn ) {
                targetZoneOffset = targetZoneOffset  + 1;
            }
        }
        var rawDatetime = left(ISO8601dateString,10) & " " & mid(ISO8601dateString,12,8);
        // adjust offset based on offset given in date string
        if (uCase(mid(ISO8601dateString,20,1)) neq "Z")
            targetZoneOffset = targetZoneOffset -  val(mid(ISO8601dateString,20,3)) ;
        return DateAdd("h", targetZoneOffset, CreateODBCDateTime(rawDatetime));
    }
}