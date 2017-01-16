using RGiesecke.DllExport;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Windows.Forms;
using System.Xml;

namespace KinyxDFeLib
{
    public class KinyxDFeLibXML
    {
        /// <summary>
        /// Assinar tag infNFe do XML utilizado certificado informado
        /// </summary>
        /// <param name="conteudoXML">Conteudo do XML a ser assinado</param>
        /// <param name="serialCertificado">Serial do certificado a ser utilizado</param>
        /// <param name="xmlAssinado">XML assinado</param>
        [DllExport(CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall)]
        public static void AssinarXML([MarshalAs(UnmanagedType.BStr)] string conteudoXML, [MarshalAs(UnmanagedType.BStr)] string serialCertificado, [MarshalAs(UnmanagedType.BStr)] out string xmlAssinado)
        {
            try
            {
                // Carregar certificado
                X509Certificate2 certificado = Utilitarios.GetCertificadoPorSerial(serialCertificado);

                // Carregar XML
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(conteudoXML);

                // Assinar infNFe
                XmlElement nodeInfNFe = xmlDoc.GetElementsByTagName("infNFe")[0] as XmlElement;

                // ID da tag
                string id = nodeInfNFe.Attributes.GetNamedItem("Id").Value;
                SignedXml signer = new SignedXml(nodeInfNFe);
                signer.SigningKey = certificado.PrivateKey;

                Reference reference = new Reference("#" + id);
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigC14NTransform());
                signer.AddReference(reference);

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(certificado));
                signer.KeyInfo = keyInfo;
                signer.ComputeSignature();

                // Conteudo da assinatura digital
                XmlElement assinatura = signer.GetXml();

                // Mesclar assinatura com NF-e
                xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(assinatura, true));

                // Retornar XML com assinatura digital
                xmlAssinado = xmlDoc.OuterXml;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                xmlAssinado = "";
            }
        }
    }
}
