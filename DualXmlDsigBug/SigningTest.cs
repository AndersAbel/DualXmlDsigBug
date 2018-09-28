using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace DualXmlDsigBug
{
    public static class SigningTest
    {
        public static void SignAndVerify()
        {
            var xml = "<xml><a ID=\"a\"/><b ID=\"b\"><c/></b></xml>";

            Console.WriteLine("Xml: " + xml);

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xml);

            using (var csp = new RSACryptoServiceProvider())
            {
                Console.WriteLine("Signing b...");

                var signedXmlB = new SignedXml(xmlDoc) { SigningKey = csp };
                var referenceB = new Reference("#b");
                referenceB.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                referenceB.AddTransform(new XmlDsigExcC14NTransform());
                signedXmlB.AddReference(referenceB);
                signedXmlB.ComputeSignature();

                var signatureNodeB = xmlDoc.ImportNode(signedXmlB.GetXml(), true);
                xmlDoc.SelectSingleNode("//c").AppendChild(signatureNodeB);
                signedXmlB.LoadXml(signatureNodeB as XmlElement);

                Console.WriteLine("Check signature B: " + CheckSignature(xmlDoc.SelectSingleNode("//c"), csp));

                Console.WriteLine("Signing a...");

                var signedXmlA = new SignedXml(xmlDoc) { SigningKey = csp };

                var referenceA = new Reference("#a");
                referenceA.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                referenceA.AddTransform(new XmlDsigExcC14NTransform());
                signedXmlA.AddReference(referenceA);
                signedXmlA.ComputeSignature();

                var signatureNodeA = xmlDoc.ImportNode(signedXmlA.GetXml(), true);
                xmlDoc.SelectSingleNode("//a").AppendChild(signatureNodeA);

                Console.WriteLine("Check signature A: " + CheckSignature(xmlDoc.SelectSingleNode("//a"), csp));
                Console.WriteLine("Check signature B: " + CheckSignature(xmlDoc.SelectSingleNode("//c"), csp));

                var childDoc = new XmlDocument();
                childDoc.LoadXml(xmlDoc.SelectSingleNode("//b").OuterXml);

                Console.WriteLine("Check signature B, in own document: " + CheckSignature(childDoc.SelectSingleNode("//c"), csp));
            }
        }

        private static bool CheckSignature(XmlNode xmlNode, RSACryptoServiceProvider csp)
        {
            var signedXml = new SignedXml(xmlNode.OwnerDocument);
            signedXml.LoadXml(xmlNode.FirstChild as XmlElement);

            return signedXml.CheckSignature(csp);
        }
    }
}
