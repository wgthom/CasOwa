CasOwa 0.6 - September 2010

CasOwa is the .NET CAS Client for Outlook Web Access (OWA).   Once installed,  users can authenticate with Jasig CAS and get access to thier inbox.
CasOwa is implemented as a .NET HttpHandler and is dependenat on the DotNetCas Client and Log4Net.

Installation Guide

0. Download src from GitHub compile and publish.

1. Copy the website to suitable location on your server

2. Create new Virtual Directory with Permissions: Read, Execute

3. Extension Mapping
* Find .aspx mapping and copy the Executable Path
* Insert... Wildcard application map using the .aspx Executable Path 

4. Make sure the coa Virtual Directory is using ASP.NET 2.0.50727
* right click virtual directory / Properties / ASP.NET / Version

5. Make sure ASP.NET 2.0 is registered with IIS.
http://forums.asp.net/t/890535.aspx
If ASP.NET 2.0 is not registered with IIS6, you need to install it:
C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727>aspnet_regiis.exe -i

6. Make sure SSL certs on IIS  and CAS are mutually trusted.

7. Configure CasOwa in Web.conf
<appSettings>
  <add key="CasOwa.ClearPassUrl" value="https://cashostname/cas/clearPass"/>
  <add key="CasOwa.OwaUrl" value="https://owahostname/owa/auth"/>
  <add key="CasOwa.OwaInboxUrl" value="https://owahostname/owa/"/>
  <add key="CasOwa.skipOwaUrlCertificateValidation" value="true" />  
</appSettings>

8. Configure DotNetCasClient in Web.conf
  <casClientConfig    casServerLoginUrl="https://cashostname/cas/login"
		serverName="https://owahostname/" 
		secureUriRegex="(?i)/auth" 
		casServerUrlPrefix="https://cashostname/cas/" 
		redirectAfterValidation="false" 
		useSession="false" 
		gateway="false" 
		renew="false" 
		ticketValidatorName="Cas20" 
		ticketTimeTolerance="5000" 
		singleSignOut="false" 
		proxyGrantingTicketReceptor="true" 
		proxyCallbackUrl="https://owahostname/coa/proxyCallback" 
		proxyReceptorUrl="/coa/proxyCallback" />

9.  Try AuthN URL:  http://https://owahostname/coa/auth

