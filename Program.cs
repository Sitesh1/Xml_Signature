using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;


namespace XmlSignature
{
    internal class Program
    {
        static void Main(string[] args)
        {
           // SignXml();
            VerifySignature();

            //XmlDocument doc = new XmlDocument();
            //doc.Load(@"D:\xml\file.xml");
            //string pfxFilePath = @"D:\pfx\pfxfile.pfx";
            //// Load the X.509 certificate from the .pfx file
            //X509Certificate2 cert = new X509Certificate2(pfxFilePath, "123");
            //SignXmlWithCertificate(doc, cert);
        }
        public static void SignXml()
        {
            try
            {

                // Load the XML document to be signed
                XmlDocument doc = new XmlDocument();
                doc.Load(@"D:\xml\file.xml");

                // Load the PFX file containing the signing certificate
                X509Certificate2 cert = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");

                // Create a SignedXml object and add the signing key
                SignedXml signedXml = new SignedXml(doc);
                signedXml.SigningKey = cert.PrivateKey;

                // Create a reference to the document to be signed
                Reference reference = new Reference();
                reference.Uri = "";

                // Add the reference to the SignedXml object
                signedXml.AddReference(reference);

                // Create a KeyInfo object and add the signing certificate
                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(cert));

                // Add the KeyInfo object to the SignedXml object
                signedXml.KeyInfo = keyInfo;

                // Compute the signature and add it to the XML document
                signedXml.ComputeSignature();
                XmlElement signatureElement = signedXml.GetXml();
                doc.DocumentElement.AppendChild(signatureElement);

                // Save the signed XML document
                doc.Save(@"D:\xml\xmlsigned.xml");

                Console.WriteLine("xml signed successfully.");
                Console.ReadLine();


            }
            catch (Exception ex)
            {
                Console.WriteLine("Error:-" + ex.Message);
                Console.ReadLine();
            }
        }

        public static void VerifySignature()
        {
            try
            {

                // Load the XML file with the signature
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(@"D:\sinednew.xml");

                // Create a new instance of the SignedXml class
                SignedXml signedXml = new SignedXml(xmlDoc);

                // Find the signature node in the XML document
                XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
                if (nodeList.Count == 0)
                {
                    throw new CryptographicException("No signature found in XML document.");
                }

                // Load the signature node into the SignedXml object
                signedXml.LoadXml((XmlElement)nodeList[0]);

                // Verify the signature
                bool isValid = signedXml.CheckSignature();
                if (isValid)
                {
                    Console.WriteLine("Digital signature is valid.");
                    Console.ReadLine();
                }
                else
                {
                    Console.WriteLine("Digital signature is invalid.");
                    Console.ReadLine();
                }




                //XmlDocument xmlDocument = new XmlDocument();
                //xmlDocument.Load(@"D:\sinedSiteshxml.xml");


                //// Create a SignedXml object and pass in the XML document
                //SignedXml signedXml = new SignedXml(xmlDocument);

                //// Find the signature node in the XML document
                //XmlNodeList signatureNodes = xmlDocument.GetElementsByTagName("Signature");
                //XmlElement signatureElement = (XmlElement)signatureNodes[0];

                //// Load the signature onto the SignedXml object
                //signedXml.LoadXml(signatureElement);

                //// Verify the signature
                //bool isValid = signedXml.CheckSignature();
                //// Print the result of the verification
                //if (isValid)
                //{
                //    Console.WriteLine("The signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("The signature is not valid.");
                //    Console.ReadLine();
                //}


                //XmlDocument xmlDoc = new XmlDocument();
                //xmlDoc.PreserveWhitespace = true;
                //xmlDoc.Load(@"D:\sinedSiteshxml.xml");
                //SignedXml signedXml = new SignedXml(xmlDoc);
                //XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
                //XmlNodeList certificates = xmlDoc.GetElementsByTagName("X509Certificate");
                //X509Certificate2 dcert2 = new X509Certificate2(Convert.FromBase64String(certificates[0].InnerText));
                //bool passes=false;
                //foreach (XmlElement element in nodeList)
                //{
                //    signedXml.LoadXml(element);
                //    passes = signedXml.CheckSignature(dcert2, true);
                //}
                //if (passes)
                //{
                //    Console.WriteLine("The signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("The signature is not valid.");
                //    Console.ReadLine();
                //}

                //var xmlDoc = new XmlDocument();
                //xmlDoc.Load(@"D:\sinedSiteshxml.xml");

                //// Create a SignedXml object and pass in the XML document
                //var signedXml = new SignedXml(xmlDoc);

                //// Find the signature element in the XML document
                //var signatureNode = xmlDoc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0];

                //// Load the signature into the SignedXml object
                //signedXml.LoadXml((XmlElement)signatureNode);

                //// Verify the signature
                //bool signatureValid = signedXml.CheckSignature();

                //XmlDocument xmlDoc = new XmlDocument();
                //xmlDoc.Load(@"D:\sinedSiteshxml.xml");

                //SignedXml signedXml = new SignedXml(xmlDoc);

                //XmlNodeList signatureNodes = xmlDoc.GetElementsByTagName("Signature");
                //signedXml.LoadXml((XmlElement)signatureNodes[0]);

                //X509Certificate2 cert = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");

                //bool isValid = signedXml.CheckSignature(cert, true);

                //if (isValid)
                //{
                //    Console.WriteLine("The XML signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("The XML signature is not valid.");
                //    Console.ReadLine();
                //}



                //XmlDocument xmlDoc = new XmlDocument();
                //xmlDoc.Load(@"D:\xml\xmlsigned.xml");

                //// Create a new SignedXml object and pass in the XML document
                //SignedXml signedXml = new SignedXml(xmlDoc);

                //// Find the signature node in the XML document
                //XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
                //signedXml.LoadXml((XmlElement)nodeList[0]);

                //// Load the PFX file containing the signer's certificate
                //X509Certificate2 cert = new X509Certificate2(@"D:\pfx\pfxfile.pfx", "123");

                //// Verify the signature using the signer's certificate
                //bool signatureValid = signedXml.CheckSignature(cert, true);
                //if (signatureValid)
                //{
                //    Console.WriteLine("Digital signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("Digital signature is invalid.");
                //    Console.ReadLine();
                //}





                //// Load the XML document to be verified
                //XmlDocument xmlDocument = new XmlDocument();
                //xmlDocument.Load(@"D:\sinedSiteshxml.xml");

                //// Create a new SignedXml object and pass in the XML document
                //SignedXml signedXml = new SignedXml(xmlDocument);

                //// Find the Signature node in the XML document
                //XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");
                //signedXml.LoadXml((XmlElement)nodeList[0]);

                //// Verify the signature using the public key of the signing certificate
                //bool isValid = signedXml.CheckSignature();

                //XmlDocument xmlDoc = new XmlDocument();
                //xmlDoc.Load(@"D:\sinedSiteshxml.xml");

                //// Create a SignedXml object and load the signature
                //SignedXml signedXml = new SignedXml(xmlDoc);
                //XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
                //signedXml.LoadXml((XmlElement)nodeList[0]);

                //// Check the signature
                //bool isSignatureValid = signedXml.CheckSignature();


                //if (isSignatureValid)
                //{
                //    Console.WriteLine("The signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("The signature is not valid.");
                //    Console.ReadLine();
                //}



                //string xmlFile = @"D:\xml\xmlsigned.xml";

                //// Load the XML file
                //XmlDocument docxml = new XmlDocument();
                //docxml.Load(xmlFile);

                //// Create a new SignedXml object
                //SignedXml signedXml = new SignedXml(docxml);

                //// Find the signature element in the XML file
                //XmlNodeList nodeList = docxml.GetElementsByTagName("Signature");
                //if (nodeList.Count == 0)
                //{
                //    Console.WriteLine("No signature found.");
                //    return;
                //}
                //signedXml.LoadXml((XmlElement)nodeList[0]);

                //// Verify the signature
                //bool signatureValid = signedXml.CheckSignature();
                //if (signatureValid)
                //{
                //    Console.WriteLine("Digital signature is valid.");
                //    Console.ReadLine();
                //}
                //else
                //{
                //    Console.WriteLine("Digital signature is invalid.");
                //    Console.ReadLine();
                //}
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("Error:-" + ex.Message);
                Console.ReadLine();
            }
        }

        public static string SignXmlWithCertificate(XmlDocument Document, X509Certificate2 cert)
        {
            try
            {
                string signatureMethod = @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                string digestMethod = @"http://www.w3.org/2001/04/xmlenc#sha256";
                // CryptoConfig.AddAlgorithm(typeof(System.Deployment.Internal.CodeSigning.RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

                XmlDocument XDoc = new XmlDocument();
                XDoc.Load(@"D:\xml\file.xml");

                RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)cert.PrivateKey;
                SignedXml signedXml = new SignedXml(XDoc);
                signedXml.SigningKey = rsaKey;
                signedXml.SignedInfo.SignatureMethod = signatureMethod;

                XmlDsigEnvelopedSignatureTransform envelopeTransform = new XmlDsigEnvelopedSignatureTransform();
                XmlDsigExcC14NTransform cn14Transform = new XmlDsigExcC14NTransform();

                Reference reference = new Reference();
                reference.Uri = "";
                reference.AddTransform(envelopeTransform);
                reference.AddTransform(cn14Transform);
                reference.DigestMethod = digestMethod;

                signedXml.AddReference(reference);

                KeyInfo keyInfo = new KeyInfo();
                KeyInfoX509Data clause = new KeyInfoX509Data();
                clause.AddSubjectName(cert.Subject);
                clause.AddCertificate(cert);
                keyInfo.AddClause(clause);
                signedXml.KeyInfo = keyInfo;
                signedXml.ComputeSignature();
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                XDoc.DocumentElement.AppendChild(XDoc.ImportNode(xmlDigitalSignature, true));
                XDoc.Save(@"D:\xml\sinedxml.xml");

                return XDoc.OuterXml;
                

            }
            catch(Exception ex)
            {
                if (ex.Message.Contains("An internal error occurred."))
                {
                    return "failed:User cancel the request";
                }
                else
                {
                    return "failed:" + ex.Message;
                }
            }
        }


    }
}
