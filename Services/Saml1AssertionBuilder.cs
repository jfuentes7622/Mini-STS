using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Services
{
    // Minimal SAML 1.1 assertion builder and XML signer.
    // Produces a signed <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion">...</Assertion>
    public class Saml1AssertionBuilder
    {
        private readonly X509Certificate2 _signingCert;

        public Saml1AssertionBuilder(X509Certificate2 signingCert)
        {
            _signingCert = signingCert ?? throw new ArgumentNullException(nameof(signingCert));
            if (!signingCert.HasPrivateKey)
                throw new ArgumentException("Signing certificate must have a private key.");
        }

        public string BuildSignedAssertion(string subjectName,
            string audienceUri,
            IDictionary<string, string> attributes,
            DateTime notBefore,
            DateTime notOnOrAfter)
        {
            var doc = new XmlDocument
            {
                PreserveWhitespace = true
            };

            var ns = "urn:oasis:names:tc:SAML:1.0:assertion";
            var assertion = doc.CreateElement("Assertion", ns);
            var assertionId = "_" + Guid.NewGuid().ToString("N");

            assertion.SetAttribute("AssertionID", assertionId);
            assertion.SetAttribute("IssueInstant", XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc));
            assertion.SetAttribute("MajorVersion", "1");
            assertion.SetAttribute("MinorVersion", "1");

            // Issuer
            var issuer = doc.CreateElement("Issuer", ns);
            issuer.InnerText = _signingCert.Subject; // or an STS identifier
            assertion.AppendChild(issuer);

            // Conditions
            var conditions = doc.CreateElement("Conditions", ns);
            conditions.SetAttribute("NotBefore", XmlConvert.ToString(notBefore, XmlDateTimeSerializationMode.Utc));
            conditions.SetAttribute("NotOnOrAfter", XmlConvert.ToString(notOnOrAfter, XmlDateTimeSerializationMode.Utc));

            if (!string.IsNullOrEmpty(audienceUri))
            {
                var audienceRestriction = doc.CreateElement("AudienceRestrictionCondition", ns);
                var audience = doc.CreateElement("Audience", ns);
                audience.InnerText = audienceUri;
                audienceRestriction.AppendChild(audience);
                conditions.AppendChild(audienceRestriction);
            }

            assertion.AppendChild(conditions);

            // AuthenticationStatement (optional, using certificate subject as auth)
            var authStmt = doc.CreateElement("AuthenticationStatement", ns);
            authStmt.SetAttribute("AuthenticationInstant", XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc));
            authStmt.SetAttribute("AuthenticationMethod", "urn:oasis:names:tc:SAML:1.0:am:unspecified");

            var subject = doc.CreateElement("Subject", ns);
            var nameIdentifier = doc.CreateElement("NameIdentifier", ns);
            nameIdentifier.InnerText = subjectName;
            subject.AppendChild(nameIdentifier);
            authStmt.AppendChild(subject);
            assertion.AppendChild(authStmt);

            // AttributeStatement
            if (attributes != null && attributes.Count > 0)
            {
                var attrStmt = doc.CreateElement("AttributeStatement", ns);
                var sub = doc.CreateElement("Subject", ns);
                var nameId = doc.CreateElement("NameIdentifier", ns);
                nameId.InnerText = subjectName;
                sub.AppendChild(nameId);
                attrStmt.AppendChild(sub);

                foreach (var kv in attributes)
                {
                    var attr = doc.CreateElement("Attribute", ns);
                    attr.SetAttribute("AttributeName", kv.Key);
                    attr.SetAttribute("AttributeNamespace", "http://schemas.xmlsoap.org/ws/2005/05/identity");
                    var attrValue = doc.CreateElement("AttributeValue", ns);
                    attrValue.InnerText = kv.Value;
                    attr.AppendChild(attrValue);
                    attrStmt.AppendChild(attr);
                }

                assertion.AppendChild(attrStmt);
            }

            doc.AppendChild(assertion);

            // Sign the assertion (enveloped signature)
            SignXmlDocument(doc, assertion, _signingCert);

            return doc.OuterXml;
        }

        private void SignXmlDocument(XmlDocument doc, XmlElement elementToSign, X509Certificate2 signingCert)
        {
            // create a SignedXml object
            var signedXml = new SignedXml(doc);
            var pk = signingCert.GetRSAPrivateKey() ?? throw new CryptographicException("No RSA private key available on signing certificate.");
            signedXml.SigningKey = pk;

            // Create a reference to be signed
            var reference = new Reference
            {
                Uri = "#" + elementToSign.GetAttribute("AssertionID")
            };

            // Transform - enveloped signature
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            // canonicalization for stable output
            var c14n = new XmlDsigExcC14NTransform();
            reference.AddTransform(c14n);

            signedXml.AddReference(reference);

            // KeyInfo (include X.509 certificate)
            var keyInfo = new KeyInfo();
            var x509Data = new KeyInfoX509Data(signingCert);
            x509Data.AddIssuerSerial(signingCert.Issuer, signingCert.SerialNumber);
            keyInfo.AddClause(x509Data);
            signedXml.KeyInfo = keyInfo;

            // Compute the signature
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and append to elementToSign
            var xmlDigitalSignature = signedXml.GetXml();
            elementToSign.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
        }
    }
}   