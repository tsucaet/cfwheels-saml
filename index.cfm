<h1>CFWheels SAML Single Sign-On</h1>

<h2>Description</h2>
<p>CFWheels plugin for authenticating users via SAML 2.0, based on the <a href="https://github.com/blueriver/MuraSAML" target="_blank">SAML integration component in Mura 7+</a></p>
<h2>Usage</h2>
<h3>Build Service Provider Metadata (first time)</h3>
<p>
    Build the XML metadata of the SAML Service Provider, providing some information: EntityID, Endpoints (Attribute Consume Service Endpoint, Single Logout Service Endpoint) and the public X.509 cert.<br />
    By default, the file saml_sp_metadata.xml will be placed in the files folder.
</p>
<pre><code>buildSPMeta(issuer, consumer, cert)</code></pre>
<h3>AuthNRequest</h3>
<p>Create a SAML AuthNRequest (for HTTP-POST binding)</p>
<pre><code>SAMLRequest = buildAuthNRequest(issuer, consumer, idpSingleSignOnService)</code></pre>
<h3>processResponse</h3>
<p>Handles building and validating a SAML response into a struct</p>
<pre><code>strResponse = processResponse(SAMLResponse)</code></pre>
