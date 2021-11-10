using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Icingaweb2AuthDemo
{
    class Program
    {
        string url;
        string hostname;
        string domain;
        string user;
        string pass;
        Regex patCSFRToken = new Regex("<input type=\"hidden\" name=\"CSRFToken\" value=\"(.*)\" id=\"CSRFToken\">");
        Regex patSessionCookie = new Regex("Icingaweb2=([A-Za-z0-9]*);");

        public Program()
        {
            hostname = System.Configuration.ConfigurationManager.AppSettings.Get("hostname");
            user = System.Configuration.ConfigurationManager.AppSettings.Get("username");
            pass = System.Configuration.ConfigurationManager.AppSettings.Get("password");
            domain = System.Configuration.ConfigurationManager.AppSettings.Get("domain");
            url = String.Format("https://{0}/icingaweb2/authentication/login", hostname);
        }

        public void Authenticate()
        {
            // First Request, to get Session-Cookie and CSRF-Token.
            //
            HttpWebRequest request = HttpWebRequest.CreateHttp(url);
            request.Method = "GET";
            CookieContainer cContainer = new CookieContainer();
            cContainer.Add(new Cookie("_chc", "1", "/icingaweb2/", domain));
            request.CookieContainer = cContainer;
            request.Headers.Add("Upgrade-Insecure-Requests", "1");
            request.Headers.Add("Sec-Fetch-Dest", "document");
            request.Headers.Add("Sec-Fetch-Mode", "navigate");
            request.Headers.Add("Sec-Fetch-Site", "none");
            request.Headers.Add("Sec-Fetch-User", "?1");
            request.Headers.Add("Cache-Control", "max-age=0");

            //Unhandled Exception: System.Net.ProtocolViolationException: Cannot send a content-body with this verb-type.

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            string key;
            Console.WriteLine("Initial-Request Response-headers");
            for (int i = 0; i < response.Headers.AllKeys.Length; i++)
            {
                Console.WriteLine(response.Headers.AllKeys[i] + " " + response.Headers.Get(response.Headers.AllKeys[i]));
            };
            Stream stream = response.GetResponseStream();
            StreamReader reader = new StreamReader(stream);
            string html = reader.ReadToEnd();
            Match mat = patCSFRToken.Match(html);
            if (mat.Success)
            {
                // Authenticate!
                Console.WriteLine(Environment.NewLine + "Authenticate" + Environment.NewLine);
                string csfr = mat.Groups[1].Value;
                Console.WriteLine("CSFR from FORM: " + csfr);
                string content = string.Format(
                    "username={0}&password={1}&redirect=&formUID=form_login&CSRFToken={2}&btn_submit=Anmelden",
                    user, pass, csfr
                );
                Console.WriteLine(content);
                request = HttpWebRequest.CreateHttp(url);
                request.Method = "POST";
                request.AllowAutoRedirect = false;
                string sessionCookie = response.Headers.Get("Set-Cookie");
                cContainer = new CookieContainer();
                mat = patSessionCookie.Match(sessionCookie);
                if (mat.Success)
                {
                    cContainer.Add(new Cookie("_chc", "1", "/icingaweb2/", "brekom.net"));
                    cContainer.Add(new Cookie("Icingaweb2", mat.Groups[1].Value, "/icingaweb2/", domain));
                    cContainer.Add(new Cookie("icingaweb2-tzo", "3600-0", "/icingaweb2/", domain));
                    request.CookieContainer = cContainer;
                    request.Accept = "*/*";
                    request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                    request.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0";
                    request.Headers.Add("Sec-Fetch-Dest", "empty");
                    request.Headers.Add("Sec-Fetch-Mode", "cors");
                    request.Headers.Add("Sec-Fetch-Site", "same-origin");
                    request.Headers.Add("X-Icinga-Accept", "text/html");
                    request.Headers.Add("X-Icinga-WindowId", "jtbiyolsakvh_nsbjgt");
                    request.Headers.Add("X-Requested-With", "XMLHttpRequest");
                    request.Headers.Add("Origin", "https://" + hostname);
                    request.Referer = url;
                    byte[] contentArray = Encoding.UTF8.GetBytes(content);
                    request.ContentLength = contentArray.Length;
                    Stream dataStream = request.GetRequestStream();
                    dataStream.Write(contentArray, 0, contentArray.Length);
                    dataStream.Close();

                    HttpWebResponse responseAuth = (HttpWebResponse)request.GetResponse();
                    Console.WriteLine(Environment.NewLine + "Authenticate Response-headers");
                    for (int i = 0; i < responseAuth.Headers.AllKeys.Length; i++)
                    {
                        Console.WriteLine(responseAuth.Headers.AllKeys[i] + " " + responseAuth.Headers.Get(responseAuth.Headers.AllKeys[i]));
                    };
                    Console.WriteLine("Auth-Response Cookies.Count " + responseAuth.Cookies.Count);
                    stream = responseAuth.GetResponseStream();
                    reader = new StreamReader(stream);
                    html = reader.ReadToEnd();

                    // Authenticated History-Request
                    //
                    string historyUrl = String.Format(
                        "https://{0}/icingaweb2/monitoring/list/eventhistory?timestamp%3E=-30%20days&state!=0&host_name=IT-FG-00916&format=json",
                        hostname
                    );
                    request = HttpWebRequest.CreateHttp(historyUrl);
                    request.Method = "GET";
                    request.Headers.Add("Upgrade-Insecure-Requests", "1");
                    request.Headers.Add("Sec-Fetch-Dest", "document");
                    request.Headers.Add("Sec-Fetch-Mode", "navigate");
                    request.Headers.Add("Sec-Fetch-Site", "none");
                    request.Headers.Add("Sec-Fetch-User", "?1");
                    request.CookieContainer = new CookieContainer();
                    request.CookieContainer.Add(new Cookie("_chc", "1", "/icingaweb2/", domain));
                    request.CookieContainer.Add(new Cookie("Icingaweb2", mat.Groups[1].Value, "/icingaweb2/", domain));
                    request.ContentType = "application/json";
                    response = (HttpWebResponse)request.GetResponse();
                    stream = response.GetResponseStream();
                    reader = new StreamReader(stream);
                    string json = reader.ReadToEnd();
                    Console.WriteLine("JSON" + json);
                }
                else
                {
                    Console.WriteLine("Unable to extract Session-Cookie from Response.");
                }
            }
            else
            {
                Console.WriteLine("Unable to extract CSFRToken from HTML-Response of first Request.");
            }
        }

        static void Main(string[] args)
        {
            Program app = new Program();
            app.Authenticate();
        }
    }
}
