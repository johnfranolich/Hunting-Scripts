/*
   Yara Rule Set
   Author: Published by Didier Stevens
   Date: 2018-07-31
   Sync Date: 
   Identifier: Fake Cert
   Reference: https://blog.nviso.be/2018/07/31/powershell-inside-a-certificate-part-1/

   Note: 
   Certificate files can be used by adversaries as a container for all kinds of payloads to avoid detection of the payload by anti-virus, IDS, … . The payload will not activate when the certificate file is opened on a Windows systems; It has to be extracted by the actor or malware
   Conclusion: every X.509 certificate encoded according to RFC 7468 starts with “—–BEGIN CERTIFICATE—–” followed by letter M.

   Inference: every certificate file containing “—–BEGIN CERTIFICATE—–” not followed by letter M can not be a valid X.509 certificate.
*/



rule certificate_payload
{
    strings:
        $re1 = /-----BEGIN CERTIFICATE-----\r\n[^M]/

    condition:
        $re1 at 0
}
