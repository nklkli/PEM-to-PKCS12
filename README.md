# PEM-to-PKCS12

This program converts a PEM certificate and a private key to the PKCS12 certificate.

Programs expects 3 command line arguments:

1. Friendly name: certificate's name (aka alias). This is free text - you are free to choose any name or sentence.

2. Certificate file: absolute path to the PEM certificate file containing public key and server info. This file content should begin with the line

`-----BEGIN CERTIFICATE-----`

3. Private key file: absolute path to the file containing private key. This file content should begin with the line

`-----BEGIN PRIVATE KEY-----`

EXAMPLE:

```pem-to-pkcs12.exe "Cool server certificate!" c:\cert.pem c:\privkey.key```

After successfull conversion the program writes a new `cert.pfx` certificate file in current directory.


# WHAT TO DO WITH cert.pfx file ?

1. Import cert.pfx certificate to Windows 'Local Computer\\Personal' store.
WARNING: Windows `User` certificate store may not be appropriate if PKCS12 certificate will be used web server.

2. Execute on command line (Administrator mode):

```netsh http add sslcert ipport=0.0.0.0:443 certhash={certThumbprint} appid={00000000-0000-0000-0000-000000000000}```

Note: `certThumbprint` is the SHA1 hex string of the PKCS12 certificate and will be displayd by the program on the console after successful cert.pfx generation.

In the screenshot you can see the imported PKCS12 certificate:
![](Certificate-Local-Computer.png)