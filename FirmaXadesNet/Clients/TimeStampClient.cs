﻿// --------------------------------------------------------------------------------------------------------------------
// TimeStampClient.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
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
using Org.BouncyCastle.Tsp;
using System.Net;
using Org.BouncyCastle.Math;
using System.IO;

namespace FirmaXadesNet.Clients
{
    class TimeStampClient
    {
        #region Public methods

        /// <summary>
        /// Realiza la petición de sellado del hash que se pasa como parametro y devuelve la
        /// respuesta del servidor.
        /// </summary>
        /// <param name="url"></param>
        /// <param name="hash"></param>
        /// <param name="certReq"></param>
        /// <returns></returns>
        public static byte[] GetTimeStamp(string url, byte[] hash, bool certReq)
        {
            TimeStampRequestGenerator tsrq = new TimeStampRequestGenerator();
            tsrq.SetCertReq(certReq);

            TimeStampRequest tsr = tsrq.Generate(TspAlgorithms.Sha1, hash, BigInteger.ValueOf(100));
            byte[] data = tsr.GetEncoded();

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/timestamp-query";
            req.ContentLength = data.Length;

            Stream reqStream = req.GetRequestStream();
            reqStream.Write(data, 0, data.Length);
            reqStream.Close();

            HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            if (res == null)
            {
                return null;
            }
            else
            {
                Stream resStream = new BufferedStream(res.GetResponseStream());
                TimeStampResponse tsRes = new TimeStampResponse(resStream);
                resStream.Close();

                return tsRes.TimeStampToken.GetEncoded();
            }
        }

        #endregion
    }
}
