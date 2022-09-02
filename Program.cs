using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using static System.Console;

string CERTIFICATE_PFX_FILENAME = "cert.pfx";

try
{
    if (args.Length != 3)
    {
        BackgroundColor = ConsoleColor.Red;
        ForegroundColor = ConsoleColor.White;
        Write("Wrong number of command line arguments!");
        resetConsole();
        ShowHelp();
        return;
    }

    string friendlyName = args[0];
    string pathToCertFile = args[1];
    string pathToPrivkeyFile = args[2];

    if (!File.Exists(pathToCertFile))
    {
        WriteLine($"File '{pathToCertFile}' doesn't exist. No output generated.");
        return;
    }

    if (!File.Exists(pathToPrivkeyFile))
    {
        WriteLine($"File '{pathToPrivkeyFile}' doesn't exist. No output generated.");
        return;
    }

    //string CERTIFICATE_PFX_PASSWORT = "edicenter"; //"1111";


    // combine private key .key file and .cer file
    string privateKeyFileContent = File.ReadAllText(pathToPrivkeyFile);
    string certFileContent = File.ReadAllText(pathToCertFile);
    string singlePem = certFileContent + privateKeyFileContent;
    PemReader pemReader = new(new StringReader(singlePem));

    List<X509CertificateEntry> chain = new();
    AsymmetricKeyParameter privKey = null;

    object o;
    while ((o = pemReader.ReadObject()) != null)
    {
        if (o is X509Certificate certificate)
        {
            chain.Add(new X509CertificateEntry(certificate));
        }
        else if (o is RsaPrivateCrtKeyParameters)
        {
            privKey = (AsymmetricKeyParameter)o;
        }
    }

    X509CertificateEntry cert = chain[0];

    BackgroundColor = ConsoleColor.Green;
    ForegroundColor = ConsoleColor.Black;
    Write("Certificate found!");
    resetConsole();
    WriteLine("Subject: " + cert.Certificate.SubjectDN);
    WriteLine("NotBefore: " + cert.Certificate.NotBefore);
    WriteLine("NotAfter: " + cert.Certificate.NotAfter);
    WriteLine("Issuer: " + cert.Certificate.IssuerDN);
    WriteLine("Serial number: " + cert.Certificate.SerialNumber);
    WriteLine("Version: " + cert.Certificate.Version);

    string validFrom = cert.Certificate.NotBefore.ToString("yyyy-MM-dd");
    string validTo = cert.Certificate.NotAfter.ToString("yyyy-MM-dd");

    friendlyName += $" {validFrom} - {validTo}";

    Pkcs12Store store = new Pkcs12StoreBuilder().Build();
    store.SetKeyEntry(
        alias: friendlyName,
        keyEntry: new AsymmetricKeyEntry(privKey),
        chain: chain.ToArray());

    byte[] certBytes = store.GetCertificate(friendlyName).Certificate.GetEncoded();
    string certThumbprint = GetSha1(certBytes);

    using FileStream p12file = File.Create(CERTIFICATE_PFX_FILENAME);

    store.Save(p12file,
               password: null /*CERTIFICATE_PFX_PASSWORT.ToCharArray()*/,
               new SecureRandom());

    p12file.Close();

    PrintSuccessMessage(certThumbprint, p12file.Name);

}
catch (Exception ex)
{
    WriteLine(ex);
}


static string GetSha1(byte[] bytes)
{
    var sha1 = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
    sha1.BlockUpdate(bytes, 0, bytes.Length);
    var data = new byte[20];
    sha1.DoFinal(data, 0);
    var fingerprint = new StringBuilder();
    for (int i = 0; i < data.Length; i++)
        fingerprint.Append(data[i].ToString("X2"));
    return fingerprint.ToString();
}


static void ShowHelp()
{
    WriteLine("This program converts a PEM certificate and a private key to the PKCS12 certificate.");
    WriteLine();
    BackgroundColor = ConsoleColor.Green;
    ForegroundColor = ConsoleColor.Black;
    Write("HOW TO USE:");
    resetConsole();
    WriteLine("Programs expects 3 command line arguments:");
    WriteLine();
    WriteLine("1. Friendly name: certificate's name (aka alias). This is free text - you are free to choose any name or sentence.");
    WriteLine();
    WriteLine($"2. Certificate file: absolute path to the PEM certificate file containing public key and server info. This file content should begin with the line {Environment.NewLine}-----BEGIN CERTIFICATE-----");
    WriteLine();
    WriteLine($"3. Private key file: absolute path to the file contains private key. This file content should begin with the line{Environment.NewLine}-----BEGIN PRIVATE KEY-----");
    WriteLine();
    BackgroundColor = ConsoleColor.Green;
    ForegroundColor = ConsoleColor.Black;
    Write("EXAMPLE:");
    resetConsole();
    WriteLine("pem-to-pfx.exe \"Cool server certificate!\" c:\\cert.pem c:\\privkey.key");
    WriteLine();
    WriteLine("After successfull conversion the program writes a new cert.pfx certificate file in current directory.");
}


static void PrintSuccessMessage(string certThumbprint, string pfxFilepath)
{
    WriteLine("--------------- FINISH ----------------");
    WriteLine($".pfx certificate file generated:");
    BackgroundColor = ConsoleColor.Green;
    ForegroundColor = ConsoleColor.Black;
    Write(pfxFilepath);
    resetConsole();
    WriteLine();   
    WriteLine("PKCS12 certificate thumbprint:");
    BackgroundColor = ConsoleColor.Green;
    ForegroundColor = ConsoleColor.Black;
    Write(certThumbprint);
    resetConsole();
    WriteLine();
    WriteLine("Further instruction: ");
    WriteLine();
    WriteLine("1. Import *.pfx certificate to Windows 'Local Computer\\Personal' store.");
    BackgroundColor = ConsoleColor.Yellow;
    ForegroundColor = ConsoleColor.Black;
    Write("WARNING: Windows User certificate store may not be appropriate if PKCS12 certificate will be used web server.");
    resetConsole();
    WriteLine();
    WriteLine("2. Execute in command line (Administrator mode):");
    WriteLine($"netsh http add sslcert ipport=0.0.0.0:443 certhash={certThumbprint} appid={{00000000-0000-0000-0000-000000000000}}");
    WriteLine("----------------------------------------");
}


static void resetConsole()
{
    ResetColor();
    WriteLine("");
}