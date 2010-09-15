#region License
/*
 * Copyright © 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#endregion

using System;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using DotNetCasClient.Security;
using DotNetCasClient.Utils;
using System.IO;
using System.Configuration;
using System.Net.Security;
using System.Text;

namespace CasOwa
{
    /// <summary>
    /// CasOwaAuthHandler provides Jasig CAS Authentiction for Microsoft Outlook Web Access.
    /// </summary>
    sealed public class CasOwaAuthHandler : IHttpHandler
    {
        /// <summary>
        /// URL of CAS ClearPass extention
        /// </summary>
        static string ClearPassUrl;

        /// <summary>
        /// URL of CAS ClearPass extention as Uri for DotNetClient API call
        /// </summary>
        static Uri ClearPassUri;

        /// <summary>
        /// CAS protocol artifact name
        /// </summary>
        static string ArtifactParameterName = "ticket";

        /// <summary>
        /// CAS protocal service name
        /// </summary>
        static string ServiceParameterName = "service";

        /// <summary>
        /// Base URL for OWA, e.g. https://hostname/owa
        /// </summary>
        static string OwaUrl;

        /// <summary>
        /// URL for OWA Auth, used to start an OWA session and retrieve sessionid and cadata.
        /// </summary>
        static string OwaAuthUrl;

        /// <summary>
        /// Option Form Fields from the OWA authentication form.
        /// </summary>
        static string OwaOptionalFormFields = "&flags=0&forcedownlevel=0";

        /// <summary>
        /// Path to OWA Auth script.
        /// </summary>
        static string OwaAuthPath = "/auth/owaauth.dll";

        /// <summary>
        /// OWA Inbox Redirect after authentication
        /// </summary>
        static string OwaInboxUrl;
        
                /// <summary>
        /// Bootstrap configuration from Web.conf.
        /// </summary>
        static CasOwaAuthHandler()
        {
            ClearPassUrl = ConfigurationManager.AppSettings.Get("CasOwa.ClearPassUrl");
            if (String.IsNullOrEmpty(ClearPassUrl)) {
                throw new ConfigurationErrorsException("ClearPassUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"ClearPassUrl\" value=\"https://cashostname/cas/clearPass\"/>");
            }

            try
            {
                ClearPassUri = new Uri(ClearPassUrl);
            }
            catch(UriFormatException ufe)
            {
                throw new ConfigurationErrorsException("ClearPassUrl is invalid.  Check your settings in <appSettings> section of <web.conf>. " + ufe.Message, ufe);
            }

            ArtifactParameterName = ConfigurationManager.AppSettings.Get("CasOwa.ArtifactParameterName") ?? ArtifactParameterName;
            ServiceParameterName = ConfigurationManager.AppSettings.Get("CasOwa.ServiceParameterName") ?? ServiceParameterName;

            OwaUrl = ConfigurationManager.AppSettings.Get("CasOwa.OwaUrl");
            if (String.IsNullOrEmpty(OwaUrl)) {
                throw new ConfigurationErrorsException("CasOwa.OwaUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasOwa.OwaAuthUrl\" value=\"https://exchangehostname/owa\"/>");
            }

            OwaAuthPath = ConfigurationManager.AppSettings.Get("CasOwa.OwaAuthPath") ?? OwaAuthPath;
            OwaAuthUrl = OwaUrl + OwaAuthPath;

            OwaOptionalFormFields = ConfigurationManager.AppSettings.Get("CasOwa.OwaOptionalFormFields") ?? OwaOptionalFormFields;

            OwaInboxUrl = ConfigurationManager.AppSettings.Get("CasOwa.OwaInboxUrl");
            
            // This is setting is neccesary when using untrusted certificates, typically in a development or testing.
            var skipOwaUrlCertificateValidation = ConfigurationManager.AppSettings.Get("CasOwa.skipOwaUrlCertificateValidation");
            if (!String.IsNullOrEmpty(skipOwaUrlCertificateValidation) && bool.Parse(skipOwaUrlCertificateValidation))
            {
                ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate {  return true; });
            }

        }

        /// <summary>
        /// This handler can be used for another request, as no state information is preserved per request.
        /// </summary>
        public bool IsReusable
        {
            get { return true; }
        }

        /// <summary>
        /// Using ProxyTickets and the ClearPass extention for CAS CasOwaAuthHandler retrieves
        /// the users credentials, POSTs them to the OWA, retrieves sessionid and cdata cookies,
        /// sets them on the browser and redirects to the user's inbox.
        /// </summary>
        /// <param name="context"></param>
        public void ProcessRequest(HttpContext context)
        {
            // Get the CAS Authenticated User
            var user = context.User as ICasPrincipal;
            if (user == null)
            {
                throw new HttpException(500, "HttpContext.Current.User is null.  Check that the DotNetCasClient is mapped and configured correctly in <web.conf>");
            }

            // Retrieve a Proxy Ticket for ClearPass
            var proxyTicket = user.GetProxyTicketFor(ClearPassUri);

            // Get the Password from ClearPass
            var clearPassRequest = ClearPassUrl + "?" + ArtifactParameterName + "=" + proxyTicket + "&" + ServiceParameterName + "=" + ClearPassUrl;
            string clearPassResponse;
            StreamReader reader = null;
            try
            {
                reader = new StreamReader(new WebClient().OpenRead(clearPassRequest));
                clearPassResponse = reader.ReadToEnd();
            }
            catch(Exception ex) {
                throw new HttpException(500, "Error getting response from clearPass at URL: " + clearPassRequest + ". " + ex.Message, ex);
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
            }
            var clearPass = XmlUtils.GetTextForElement(clearPassResponse, "cas:credentials");
            if(String.IsNullOrEmpty(clearPass)) {
                throw new HttpException(500, "Received response from " + clearPassRequest + ", but cas:credientials IsNullOrEmpty.  Check CAS server logs for errors.  Make sure SSL certs are trusted.");
            }

            // POST username/password to owaauth.dll to get sessionid and cadata cookies
            var owaAuthFormFields = "destination=" + OwaUrl 
                                  + "&username=" + user.Identity.Name
                                  + "&password=" + HttpUtility.UrlEncode(clearPass, Encoding.ASCII)
                                  + OwaOptionalFormFields;
            var postData = System.Text.Encoding.UTF8.GetBytes(owaAuthFormFields);
            var request = (HttpWebRequest)WebRequest.Create(OwaUrl + OwaAuthPath);
            request.AllowAutoRedirect = false;
            request.CookieContainer = new CookieContainer();
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = postData.Length;
            Stream requestStream = null;
            try {
                requestStream = request.GetRequestStream();
                requestStream.Write(postData, 0, postData.Length);
            } 
            catch(Exception ex){
                throw new HttpException(500, "Error POSTing Auth Form to " + OwaAuthUrl + ". " + ex.Message, ex);
            }
            finally 
            {
                if (requestStream != null) {
                    requestStream.Close();
                }
            }

            HttpWebResponse response = null;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (Exception ex)
            {
                throw new HttpException(500, "Error getting Response from " + OwaAuthUrl + ". " + ex.Message, ex);
            }
            finally
            {
                if (response != null) {
                    response.Close();
                }
            }

            // Send sessionid and cadata cookies back to the browser and redirect to Owa
            foreach (Cookie cookie in response.Cookies)
            {
                context.Response.Cookies.Add(new HttpCookie(cookie.Name, cookie.Value));
            }

            string redirectUrl;
            if (String.IsNullOrEmpty(OwaInboxUrl))
            {
                redirectUrl = response.GetResponseHeader("Location");
            }
            else
            {
                redirectUrl = OwaInboxUrl;
            }
            context.Response.Redirect(redirectUrl);
         }
     }
}

