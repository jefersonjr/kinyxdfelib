using RGiesecke.DllExport;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Windows.Forms;
using System.Xml;

namespace KinyxDFeLib
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Certificado
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 50)]
        public string SerialNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Subject;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 255)]
        public string IssuerName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 15)]
        public string CNPJ;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
        public string ExpirationDate;

        [MarshalAs(UnmanagedType.U1)]
        public bool IsHardwareDevice;
    }

    public class KinyxDFeLibXML
    {
        /// <summary>
        /// Assinar tag infNFe do XML utilizado certificado informado
        /// </summary>
        /// <param name="conteudoXML">Conteudo do XML a ser assinado</param>
        /// <param name="serialCertificado">Serial do certificado a ser utilizado</param>
        /// <param name="xmlAssinado">XML assinado</param>
        [DllExport(CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall)]
        public static void AssinarXML([MarshalAs(UnmanagedType.BStr)] string conteudoXML, [MarshalAs(UnmanagedType.BStr)] string serialCertificado, [MarshalAs(UnmanagedType.BStr)] string infElement, [MarshalAs(UnmanagedType.BStr)] out string xmlAssinado)
        {
            try
            {
                // Carregar certificado
                X509Certificate2 certificado = Utilitarios.GetCertificadoPorSerial(serialCertificado);

                // Carregar XML
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(conteudoXML);

                // Obter nó a ser assinado
                XmlNodeList nodeElementList = xmlDoc.GetElementsByTagName(infElement);

                if (nodeElementList.Count == 0)
                    throw new Exception(String.Format("Elemento {0} não encontrado no XML informado.", infElement));

                // Obter primeiro nó encontrado
                XmlElement nodeElement = nodeElementList[0] as XmlElement;

                // ID da tag
                string id = nodeElement.Attributes.GetNamedItem("Id").Value;
                SignedXml signer = new SignedXml(nodeElement);
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
                // MSG PARA DEBUG
                MessageBox.Show(ex.Message);
                xmlAssinado = "";
            }
        }

        [DllExport(CallingConvention = CallingConvention.StdCall)]
        public static void SelecionarCertificado([MarshalAs(UnmanagedType.BStr)] string numeroSerie, IntPtr ptrCertificado)
        {
            try
            {
                // Certificado selecionado - retornar para aplicação
                X509Certificate2 certificado = default(X509Certificate2);

                // Abrir seleção de certificado digital
                X509Certificate2Collection certificados = Utilitarios.CarregarCertificados();

                // Se não informado serial, abrir seleção de certificado
                if (string.IsNullOrEmpty(numeroSerie))
                {
                    X509Certificate2Collection certSelecionado = X509Certificate2UI.SelectFromCollection(certificados, "Certificados", "Selecionar certificado digital", X509SelectionFlag.SingleSelection);

                    if (certSelecionado.Count > 0)
                        certificado = certSelecionado[0];
                }
                else
                {
                    // Se informado número de série, procurar diretamente o certificado
                    X509Certificate2Collection lstCert = certificados.Find(X509FindType.FindBySerialNumber, numeroSerie, false);

                    if (lstCert.Count > 0)
                        certificado = lstCert[0];
                }

                // Obter estrutura através do ponteiro informado
                Certificado cert = (Certificado)Marshal.PtrToStructure(ptrCertificado, typeof(Certificado));

                // Preencher dados do certificado digital
                cert.SerialNumber = certificado.SerialNumber;
                cert.Subject = certificado.Subject;
                cert.ExpirationDate = certificado.GetExpirationDateString();
                cert.IssuerName = certificado.IssuerName.Format(false);
                cert.IsHardwareDevice = false;

                if(certificado.HasPrivateKey)
                {
                    AsymmetricAlgorithm privKey = certificado.PrivateKey;
                    RSACryptoServiceProvider provider = (privKey as RSACryptoServiceProvider);

                    if (provider != null)
                        cert.IsHardwareDevice = provider.CspKeyContainerInfo.HardwareDevice;
                }

                // Obter CNPJ das propriedades
                foreach (X509Extension ext in certificado.Extensions)
                {
                    string propriedades = ext.Format(true);

                    if (propriedades.IndexOf("2.16.76.1.3.3") >= 0)
                    {
                        string[] propLinhas = propriedades.Split('\n');

                        foreach (string linha in propLinhas)
                        {
                            if (linha.IndexOf("2.16.76.1.3.3") >= 0)
                            {
                                int posicaoSeparador = linha.IndexOf("=");
                                cert.CNPJ = Utilitarios.ConverterHexToAscii(linha.Substring(posicaoSeparador + 1, linha.Length - posicaoSeparador - 2));
                            }
                        }
                    }
                }

                // Realocar estrutura alterada para o ponteiro
                Marshal.StructureToPtr(cert, ptrCertificado, false);
            }
            catch (Exception ex)
            {
                //DEBUG
                MessageBox.Show(ex.Message);
            }
        }
    }
}
