using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KinyxDFeLib
{
    public static class Utilitarios
    {
        public static X509Certificate2 GetCertificadoPorSerial(string numeroSerial)
        {
            X509Store certStore = new X509Store("MY", StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection findCert = certStore.Certificates.Find(X509FindType.FindBySerialNumber, numeroSerial, false);

            if (findCert.Count > 0)
                return findCert[0];
            else
                throw new Exception(String.Format("Certificado com o serial '{0}' não encontrado.", numeroSerial));
        }
    }
}
