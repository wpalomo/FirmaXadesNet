// --------------------------------------------------------------------------------------------------------------------
// XMLUtil.cs
//
// FirmaXadesNet - Librería para generación de firmas XADES
// Copyright (C) 2014 Dpto. de Nuevas Tecnologías de la Concejalía de Urbanismo de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// Contact info: J. Arturo Aguado
// Email: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Collections;
using Microsoft.Xades;
using System.Security.Cryptography;

namespace FirmaXadesNet
{
    class XMLUtil
    {
        /// <summary>
        /// Calcula el valor hash para los elementos especificados en elementXpaths
        /// </summary>
        /// <param name="signatureXmlElement"></param>
        /// <param name="elementXpaths"></param>
        /// <returns></returns>
        public static byte[] ComputeHashValueOfElementList(XmlElement signatureXmlElement, ArrayList elementXpaths)
        {
            XmlDocument xmlDocument;
            XmlNamespaceManager xmlNamespaceManager;
            XmlNodeList searchXmlNodeList;
            XmlDsigC14NTransform xmlDsigC14NTransform;
            MemoryStream msResult = new MemoryStream();
            byte[] retVal;
            UTF8Encoding encoding = new UTF8Encoding(false);

            xmlDocument = signatureXmlElement.OwnerDocument;
            xmlNamespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

            // obtiene los namespaces del elemento raiz, necesarios para calcular el hash de una firma enveloped
            Dictionary<string, string> namespaces = new Dictionary<string, string>();

            if (xmlDocument.DocumentElement != null)
            {
                foreach (XmlAttribute attr in xmlDocument.DocumentElement.Attributes)
                {
                    if (attr.Name.StartsWith("xmlns"))
                    {
                        namespaces.Add(attr.Name, attr.Value);
                    }
                }
            }

            foreach (string elementXpath in elementXpaths)
            {
                searchXmlNodeList = signatureXmlElement.SelectNodes(elementXpath, xmlNamespaceManager);

                if (searchXmlNodeList.Count == 0)
                {
                    throw new CryptographicException("Element " + elementXpath + " not found while calculating hash");
                }

                foreach (XmlNode xmlNode in searchXmlNodeList)
                {
                    if (xmlNode.Name == "ds:SignatureValue")
                    {
                        XmlAttribute xadesNamespace = xmlDocument.CreateAttribute("xmlns:" + XadesSignedXml.XmlXadesPrefix);
                        xadesNamespace.Value = XadesSignedXml.XadesNamespaceUri;
                        xmlNode.Attributes.Append(xadesNamespace);
                    }
                    else
                    {
                        XmlAttribute xadesNamespace = xmlDocument.CreateAttribute("xmlns:" + XadesSignedXml.XmlDSigPrefix);
                        xadesNamespace.Value = XadesSignedXml.XmlDsigNamespaceUrl;
                        xmlNode.Attributes.Append(xadesNamespace);
                    }

                    foreach (var attr in namespaces)
                    {
                        XmlAttribute attrNamespace = xmlDocument.CreateAttribute(attr.Key);
                        attrNamespace.Value = attr.Value;
                        xmlNode.Attributes.Append(attrNamespace);  
                    }

                    byte[] buffer = encoding.GetBytes(xmlNode.OuterXml);
                    
                    using (MemoryStream ms = new MemoryStream(buffer))
                    {
                        xmlDsigC14NTransform = new XmlDsigC14NTransform();
                        xmlDsigC14NTransform.LoadInput(ms);
                        MemoryStream canonicalizedStream = (MemoryStream)xmlDsigC14NTransform.GetOutput(typeof(Stream));
                        canonicalizedStream.Flush();
                        canonicalizedStream.WriteTo(msResult);                    
                    }
                }
            }

            using (SHA1 sha1 = SHA1.Create())
            {
                retVal = sha1.ComputeHash(msResult.ToArray());
            }

            msResult.Dispose();

            return retVal;
        }
    }
}
