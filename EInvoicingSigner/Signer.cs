/**
* Original for from <BassemAgmi> https://github.com/bassemAgmi/EInvoicingSigner
*
***************** CHANGE lOG **************************
*
* 2022-06-24 Added XML support (V1.1).
* By Abdelrahman Helaly < AH3laly@gmail.com - https://Github.com/AH3laly >
*
*/

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.IO;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

public class TokenSigner
{
    private readonly string DllLibPath = "eps2003csp11.dll";
    private string TokenPin = "999999999";
    private string TokenCertificate = "Egypt Trust Sealing CA";
    private string InputFileFormat = "";
    
    private string JSONFileName = "SourceDocumentJson.json";
    private string XMLFileName = "SourceDocumentXml.xml";

    private static TokenSigner tokenSigner;

    public static void Main(String[] args)
    {
        try {
            TokenSigner.tokenSigner = new TokenSigner();
            
            if (args == null || args.Length == 0)
            {
                tokenSigner.ListCertificates();
                Console.WriteLine("Help.");
                Console.WriteLine("First argument is the folder path.");
                Console.WriteLine("Second argument is the token pin.");
                Console.WriteLine("Third argument is the certificate issuer.");
                Console.WriteLine("Fourth argument is the format e.g XML or JSON.");
            }
            else
            {
                Console.WriteLine("First argument "+ args[0]);
                if (args.Length >= 2)
                {
                    Console.WriteLine("Second argument " + args[1]);
                    tokenSigner.TokenPin = args[1];
                }
                if (args.Length >= 3)
                {
                    Console.WriteLine("Third argument " + args[2]);
                    tokenSigner.TokenCertificate = args[2];
                }
                if (args.Length >= 4)
                {
                    Console.WriteLine("Fourth argument " + args[3]);
                    tokenSigner.InputFileFormat = args[3].ToUpper();;
                }

                string path = args[0];
                string inputFile = "";

                if(tokenSigner.InputFileFormat == "JSON")
                {
                    // Explicitly requested JSON format
                    inputFile = path + @"\" + tokenSigner.JSONFileName;
                }
                else if(tokenSigner.InputFileFormat == "XML")
                {
                    // Explicitly requested XML format
                    inputFile = path + @"\" + tokenSigner.XMLFileName;
                }
                else if (File.Exists(path + @"\" + tokenSigner.JSONFileName) == true)
                {
                    // Fallback to JSON format if no format was specified in the parameters
                    tokenSigner.InputFileFormat = "JSON";
                    inputFile = path + @"\" + tokenSigner.JSONFileName;
                }
                else if (File.Exists(path + @"\" + tokenSigner.XMLFileName) == true)
                {
                    // Otherwise use the XML format
                    tokenSigner.InputFileFormat = "XML";
                    inputFile = path + @"\" + tokenSigner.XMLFileName;
                }
                
                if(inputFile == "")
                {
                    Console.WriteLine("Either File " + path + @"\" + tokenSigner.JSONFileName + " OR " + tokenSigner.JSONFileName + " is required");
                    return;
                }

                if(tokenSigner.InputFileFormat == "JSON")
                {
                    tokenSigner.processJSON(path);
                }
                else if(tokenSigner.InputFileFormat == "XML")
                {
                    tokenSigner.processXML(path);
                }
            }
        }
        catch(Exception e)
        {
            Console.WriteLine("\r\n\r\nError: " + e.Message + "\r\n\r\n");
            return;
        }
    }
    
    private void processXML(string path) {
        String cades = "";
        String SourceDocumentXml = File.ReadAllText(path + @"\" + tokenSigner.XMLFileName);
        String canonicalString = tokenSigner.SerializeXML(SourceDocumentXml);
        Regex regex;
        Match match;
        File.WriteAllBytes(path + @"\CanonicalString.txt", System.Text.Encoding.UTF8.GetBytes(canonicalString));
        
        // retrieve cades
        regex = new Regex("<documentTypeVersion>(.*)</documentTypeVersion>", RegexOptions.IgnoreCase);
        match = regex.Match(SourceDocumentXml);
        if (match.Success && match.Groups[1].ToString() == "0.9")
        {
            cades = "ANY";
        }
        else
        {
            cades = tokenSigner.SignWithCMS(canonicalString);
        }

        File.WriteAllBytes(path + @"\Cades.txt", System.Text.Encoding.UTF8.GetBytes(cades));
        
        // Create signatures XML element
        String signaturesElement = "<signatures>\r\n";
        signaturesElement += "<signature>\r\n";
        signaturesElement += "<signatureType>I</signatureType>\r\n";
        signaturesElement += "<value>" + cades + "</value>\r\n";
        signaturesElement += "</signature>\r\n";
        signaturesElement += "</signatures>\r\n";

        // Get XML Document content
        regex = new Regex("<document>((.|\r|\n|\r\n)*)</document>", RegexOptions.IgnoreCase);
        match = regex.Match(SourceDocumentXml);
        String documentContent = "";
        if(match.Success){
            documentContent = match.Groups[1].ToString();
        } else {
            throw new Exception("Invalid XML document.");
        }

        String fullSignedDocument = "<submission>\r\n";
        fullSignedDocument += "<documents>\r\n";
        fullSignedDocument += "<document>\r\n";
        fullSignedDocument += documentContent;
        fullSignedDocument += signaturesElement;
        fullSignedDocument += "</document>\r\n";
        fullSignedDocument += "</documents>\r\n";
        fullSignedDocument += "</submission>";

        // Now let's make the XML Beautiful
        try
        {
            XDocument doc = XDocument.Parse(fullSignedDocument);
            fullSignedDocument = doc.ToString();
        }
        catch (Exception e)
        {
            throw new Exception("Unable to beautify the XML file.", e);
        }

        File.WriteAllBytes(path + @"\FullSignedDocument.xml", System.Text.Encoding.UTF8.GetBytes(fullSignedDocument));
    }

    private void processJSON(string path) {
        String cades = "";
        String SourceDocumentJson = File.ReadAllText(path + @"\" + this.JSONFileName);
        JObject request = JsonConvert.DeserializeObject<JObject>(SourceDocumentJson, new JsonSerializerSettings()
        {
            FloatFormatHandling = FloatFormatHandling.String,
            FloatParseHandling = FloatParseHandling.Decimal,
            DateFormatHandling = DateFormatHandling.IsoDateFormat,
            DateParseHandling = DateParseHandling.None
        });

        //Start serialize
        String canonicalString = tokenSigner.SerializeJSON(request);
        File.WriteAllBytes(path + @"\CanonicalString.txt", System.Text.Encoding.UTF8.GetBytes(canonicalString));
        
        // retrieve cades
        if (request["documentTypeVersion"].Value<string>() == "0.9")
        {
            cades = "ANY";
        }
        else
        {
            cades = tokenSigner.SignWithCMS(canonicalString);
        }
        
        File.WriteAllBytes(path + @"\Cades.txt", System.Text.Encoding.UTF8.GetBytes(cades));
        JObject signaturesObject = new JObject(
                                new JProperty("signatureType", "I"),
                                new JProperty("value", cades));
        JArray signaturesArray = new JArray();
        signaturesArray.Add(signaturesObject);
        request.Add("signatures", signaturesArray);
        String fullSignedDocument = "{\"documents\":[" + request.ToString() + "]}";
        File.WriteAllBytes(path + @"\FullSignedDocument.json", System.Text.Encoding.UTF8.GetBytes(fullSignedDocument));
    }

    public string SerializeXML(string xmlString)
    {
        string rResult = xmlString;
    
        // Remove Indentations before tags
        result = Regex.Replace(result, @"\n[ ]+<", "\n<", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        // Remove Indentations after tags
        result = Regex.Replace(result, @">[ ]+\n", ">\n", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        // Quotate Values
        result = Regex.Replace(result, @">([:\. \p{L}\p{N}_-]+)</", ">\"$1\"</", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        // Remove Closing Tags e.g: </someTag>
        result = Regex.Replace(result, @"</([0-9a-zA-Z ]+)>", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        // Convert Tag names to Upper Case and Clean Spaces e.g <tagname /> to <TAGNAME/> and <tagname> to <TAGNAME>
        result = Regex.Replace(result, @"<([0-9a-zA-Z ]+)/?>", m => m.ToString().ToUpper().Replace(" ",""), RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        // Quotate Single Tags e.g: <TAGNAME/> to "TAGNAME"""
        result = Regex.Replace(result, @"<([0-9a-zA-Z ]+)/>", "\"$1\"\"\"", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        // Quotate Tags e.g: <TAGNAME> to "TAGNAME"
        result = Regex.Replace(result, @"<([0-9a-zA-Z ]+)>", "\"$1\"", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        // Remove newlines and carriage returns e.g \r\n, \r and \n
        result = Regex.Replace(result, @"\r\n|\r|\n", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
    
        return result;
    }
    
    private byte[] Hash(string input)
    {
        using (SHA256 sha = SHA256.Create())
        {
            var output = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return output;
        }
    }

    private byte[] HashBytes(byte[] input)
    {
        using (SHA256 sha = SHA256.Create())
        {
            var output = sha.ComputeHash(input);
            return output;
        }
    }

    public string SignWithCMS(String serializedText)
    {
        byte[] data = Encoding.UTF8.GetBytes(serializedText);
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
        {
            ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();

            if (slot is null)
            {
                return "No slots found";
            }

            ITokenInfo tokenInfo = slot.GetTokenInfo();

            ISlotInfo slotInfo = slot.GetSlotInfo();

            using (var session = slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(TokenPin));

                var certificateSearchAttributes = new List<IObjectAttribute>()
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                };

                IObjectHandle certificate = session.FindAllObjects(certificateSearchAttributes).FirstOrDefault();

                if (certificate is null)
                {
                    return "Certificate not found";
                }

                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.MaxAllowed);

                // find cert by thumbprint
                var foundCerts = store.Certificates.Find(X509FindType.FindByIssuerName, TokenCertificate, false);

                //var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);

                if (foundCerts.Count == 0)
                {
                    return "no device detected";
                }

                var certForSigning = foundCerts[0];
                store.Close();

                ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);
                SignedCms cms = new SignedCms(content, true);
                
                EssCertIDv2 bouncyCertificate = new EssCertIDv2(
                    new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), 
                    this.HashBytes(certForSigning.RawData)
                );
                
                SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });
                CmsSigner signer = new CmsSigner(certForSigning);

                signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");
                signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
                signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));
                cms.ComputeSignature(signer);
                var output = cms.Encode();

                return Convert.ToBase64String(output);
            }
        }
    }

    public string SerializeJSON(JObject request)
    {
        return SerializeJSONToken(request);
    }

    private string SerializeJSONToken(JToken request)
    {
        string serialized = "";
        if (request.Parent is null)
        {
            SerializeJSONToken(request.First);
        }
        else
        {
            if (request.Type == JTokenType.Property)
            {
                string name = ((JProperty)request).Name.ToUpper();
                serialized += "\"" + name + "\"";
                foreach (var property in request)
                {
                    if (property.Type == JTokenType.Object)
                    {
                        serialized += SerializeJSONToken(property);
                    }
                    if (property.Type == JTokenType.Boolean || property.Type == JTokenType.Integer || property.Type == JTokenType.Float || property.Type == JTokenType.Date)
                    {
                        serialized += "\"" + property.Value<string>() + "\"";
                    }
                    if(property.Type == JTokenType.String)
                    {
                        serialized +=  JsonConvert.ToString(property.Value<string>()) ;
                    }
                    if (property.Type == JTokenType.Array)
                    {
                        foreach (var item in property.Children())
                        {
                            serialized += "\"" + ((JProperty)request).Name.ToUpper() + "\"";
                            serialized += SerializeJSONToken(item);
                        }
                    }
                }
            }
            // Added to fix "References"
            if (request.Type == JTokenType.String)
            {
                serialized += JsonConvert.ToString(request.Value<string>());
            }
        }
        if (request.Type == JTokenType.Object)
        {
            foreach (var property in request.Children())
            {

                if (property.Type == JTokenType.Object || property.Type == JTokenType.Property)
                {
                    serialized += SerializeJSONToken(property);
                }
            }
        }

        return serialized;
    }

    public void ListCertificates()
    {
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.MaxAllowed);
        X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
        X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);
        foreach (X509Certificate2 x509 in fcollection)
        {
            try
            {
                byte[] rawdata = x509.RawData;
                Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);               
                x509.Reset();
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("Information could not be written out for this certificate.");
                throw ex;
            }
        }
        store.Close();       
    }
}