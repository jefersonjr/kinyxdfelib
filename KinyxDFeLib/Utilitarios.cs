using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KinyxDFeLib
{
    public static class Utilitarios
    {
        public static X509Certificate2Collection CarregarCertificados()
        {
            X509Store certStore = new X509Store("MY", StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return certStore.Certificates;
        }

        public static X509Certificate2 GetCertificadoPorSerial(string numeroSerial)
        {
            X509Certificate2Collection findCert = CarregarCertificados().Find(X509FindType.FindBySerialNumber, numeroSerial, false);

            if (findCert.Count > 0)
                return findCert[0];
            else
                throw new Exception(String.Format("Certificado com o serial '{0}' não encontrado.", numeroSerial));
        }

        public static string ConverterHexToAscii(string hexString)
        {
            hexString = hexString.Replace(" ", "");

            string asciiString = "";
            for (int i = 0; i < hexString.Length; i += 2)
            {
                if (hexString.Length >= i + 2)
                {
                    String hs = hexString.Substring(i, 2);
                    char tmpChar = System.Convert.ToChar(System.Convert.ToUInt32(hexString.Substring(i, 2), 16));

                    if (char.IsDigit(tmpChar))
                        asciiString += tmpChar.ToString();
                }
            }

            return asciiString;
        }
    }
}
