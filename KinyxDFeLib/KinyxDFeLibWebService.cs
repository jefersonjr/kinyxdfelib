using RGiesecke.DllExport;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KinyxDFeLib
{
    public class KinyxDFeLibWebService
    {
        [DllExport(CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall)]
        public static void EnviarReq([MarshalAs(UnmanagedType.BStr)] string wsURL, [MarshalAs(UnmanagedType.BStr)] string conteudoXML, [MarshalAs(UnmanagedType.BStr)] string actionWS, [MarshalAs(UnmanagedType.BStr)] string serialCertificado, [MarshalAs(UnmanagedType.BStr)] out string retornoWS)
        {
            try
            {
                // Criar WebRequest
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(wsURL);
                webRequest.Headers.Add(String.Concat("SOAPAction: \"", actionWS, "\""));
                webRequest.ContentType = "application/soap+xml; charset=utf-8;";
                webRequest.Accept = "utf-8";
                webRequest.Method = "POST";

                // Carregar certificado digital
                X509Certificate2 certificado = Utilitarios.GetCertificadoPorSerial(serialCertificado);
                webRequest.ClientCertificates.Add(certificado);

                // Carregar conteúdo a ser enviado
                byte[] dataXML = UTF8Encoding.UTF8.GetBytes(conteudoXML);

                // Gravar tamanho e conteudo na requisição
                webRequest.ContentLength = dataXML.Length;
                Stream reqStream = webRequest.GetRequestStream();
                reqStream.Write(dataXML, 0, dataXML.Length);
                reqStream.Close();

                // Obter resposta do servidor
                using (WebResponse response = webRequest.GetResponse())
                {
                    // Carregar retorno para string e retornar
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        retornoWS = reader.ReadToEnd();
                    }
                }
            }
            catch(Exception ex)
            {
                retornoWS = String.Concat("EX:", ex.Message);
            }
        }
    }
}
