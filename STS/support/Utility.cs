using FSCA.CertProcessing;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
//using System.Reflection.PortableExecutable;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace FSCA.Support
{
    internal class Utility
    {
        //public static SmartCardConfig GetConfig(Stream stm, ILogger? logger = null)
        //{
        //    string config = "";
        //    try
        //    {
        //        // load the config file
        //        using (StreamReader reader = new StreamReader(stm, Encoding.UTF8))
        //        {
        //            config = reader.ReadToEnd();
        //            JsonSerializerOptions options = new JsonSerializerOptions();
        //            var result = JsonSerializer.Deserialize<SmartCardConfig>(config, options);
        //            if (result == null)
        //            {
        //                logger?.LogError("Utility.GetConfig: Deserialization returned null SmartCardConfig.");
        //                throw new InvalidOperationException("Deserialization returned null SmartCardConfig.");
        //            }
        //            logger?.LogDebug("Utility.GetConfig: Successfully loaded SmartCardConfig.");
        //            return result;
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        logger?.LogError(e, "Utility.GetConfig: Failed to load/parse SmartCard config.");
        //    }
        //    return new SmartCardConfig();
        //}

        public static List<PKIAuthInfo> GetParseConfig(string? configPathSetting)
        {
            List<PKIAuthInfo>? defaults = null;

            // Resolve smartcard config path from appsettings; default to Default.json in project
            configPathSetting = configPathSetting ?? "Default.json";
            var configPath = Path.IsPathRooted(configPathSetting)
                ? configPathSetting
                : Path.Combine(Environment.CurrentDirectory, configPathSetting);

            // Fix CS8602: Check if Config is not null and Config.DefaultConfigpath is not null or empty before accessing
            if (configPathSetting != null)
            {
                // string configPath = Config.DefaultConfigpath;
                //Serializer pulls the file and reads t the object
                DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(List<PKIAuthInfo>));
                using (FileStream FileStrm = new FileStream(configPath, FileMode.Open))
                {
                    FileStrm.Position = 0;

                    // Fix CS8600: Converting null literal or possible null value to non-nullable type.
                    var result = ser.ReadObject(FileStrm) as List<PKIAuthInfo>;
                    defaults = result ?? new List<PKIAuthInfo>();
                }
            }

            return defaults ?? new List<PKIAuthInfo>();
        }

        public static string GetPersonna(string val)
        {
            string? _PersonalTypeStr = null;

            string _san = val ?? string.Empty;

            if (!_san.Contains("@"))
            {
                _san += "@";
            }

            if (!string.IsNullOrEmpty(_san))
            {
                if (_san.Contains(".E@") || _san.Contains(".O@"))
                {
                    //Contractor
                    _PersonalTypeStr = "CTR";
                }

                if (_san.Contains(".A@") || _san.Contains(".J@") || _san.Contains(".N@") || _san.Contains(".V@") || _san.Contains(".Q@"))
                {
                    //Military
                    _PersonalTypeStr = "MIL";
                }

                if (_san.Contains(".B@") || _san.Contains(".C@") || _san.Contains(".I@"))
                {
                    //CIV
                    _PersonalTypeStr = "CIV";
                }

                if (_san.Contains(".M@"))
                {
                    //NGO
                    _PersonalTypeStr = "NGO";
                }

                if (_san.Contains(".T@"))
                {
                    //Foreign Military
                    _PersonalTypeStr = "FM";
                }

                if (_san.Contains(".U@"))
                {
                    //Foreign Citizen
                    _PersonalTypeStr = "FN";
                }

                if (_san.Contains(".K@"))
                {
                    //Non-appropriated fund Dod/Uniformed service employee
                    _PersonalTypeStr = "NAF";
                }

                if (_san.Contains(".R@"))
                {
                    //Retired Military reciving retired pay
                    _PersonalTypeStr = "RET";
                }

                if (_san.Contains(".F@"))
                {
                    //Former Military general discharge (not retired)
                    _PersonalTypeStr = "VET";
                }

                if (_san.Contains(".ADMS"))
                {
                    //Admin Token
                    _PersonalTypeStr = "ADM";
                }
            }
            return _PersonalTypeStr ?? string.Empty;
        }

        public static string ProcessQuery(string query, string inputStr)
        {
            string? result;


            //getpart is the section here to run in
            //Example "0;,|1;=|0;."
            //the "|" seperates function from the rest
            //the ";" seperates the index item from the seperator at each level
            //the levels go as deep as the string is, for example the above is 3 levels deep

            //Sample value as "CN = Doe.John.Nancy.15044544525, OU = CONTRACTOR, OU = PKI, OU = DoD, O = U.S. Government, C = US"
            //Three levels deep example
            //To get first name (John) then the following is passed "0;,|1;=|1;." 
            //One level deep example
            //when sample is "email = johndoe@bikes.com"
            //the following is passed "getpart|1;="
            //Two level deep example
            //when sample is "firstname = john, lastname = doe" and you want last name
            //the following is passed "getpart|1;,|1;="


            string[] levels = (query ?? "").Split('|');
            result = inputStr;

            foreach (string level in levels)
            {
                result = GetPart(result, level);
            }

            return result;
        }

        private static string GetPart(string value, string level)
        {
            if (value == null) { return string.Empty; }
            //Process given level and return
            string resultstr = string.Empty;
            if (level.Contains(';'))
            {
                char Levelsep = level.Split(';')[1].ToString()[0];
                int Levelindex = int.Parse(level.Split(';')[0].ToString());
                if (value.Contains(Levelsep))
                {
                    try
                    {
                        resultstr = value.Split(Levelsep)[Levelindex].ToString();
                    }
                    catch { resultstr = string.Empty; }
                }
                else
                {
                    resultstr = value;
                }
            }
            return resultstr;
        }

        [SupportedOSPlatform("windows")]
        public static bool IsWindowsUser(string upn, ILogger? logger = null)
        {
            try
            {
                using var entry = new System.DirectoryServices.DirectoryEntry();
                logger?.LogInformation("STS:IsWindowsUser: UPN={UPN} - checking for Windows user", upn);
                var findUser = new System.DirectoryServices.DirectorySearcher(entry);
                findUser.Filter = "(&(objectClass=User)(userprincipalname=" + upn + "))";
                findUser.PropertiesToLoad.Add("userprincipalname");

                var usr = findUser.FindOne();

                if (usr != null)
                {
                    logger?.LogInformation("STS:IsWindowsUser: UPN={UPN} - found Windows user", upn);
                    return true;
                }
                logger?.LogInformation("STS:IsWindowsUser: UPN={UPN} - not a Windows user", upn);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "STS:IsWindowsUser: Exception while checking UPN={UPN}", upn);
            }
            return false;
        }

    }
}
