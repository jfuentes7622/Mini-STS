using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Extensions.Logging.ApplicationInsights;
using Microsoft.Extensions.Logging.EventLog;
using System.Net;
using Microsoft.ApplicationInsights.WorkerService;
using System.Runtime.CompilerServices;
using System.Configuration;
using System.Runtime.Versioning;

namespace FSCA.Support
{
    public class AppLogger : IDisposable
    {
        public ILogger Logger { get; set; }
        public TelemetryClient TelemetryClientObj { get; set; }

        InMemoryChannel channel = new InMemoryChannel();

        string _connStr = string.Empty;
        string _appName = string.Empty;
        static string _logName = "Federal SmartCard Adapter";
        static string _sourceName = "FSCA";

        public static ILogger<SmartCardCertAdapter> CreateLogger(InMemoryChannel channel, string connstr, string appname, out TelemetryClient telemetryClient)
        {
            try
            {
                IServiceCollection services = new ServiceCollection();
                services.AddApplicationInsightsTelemetryWorkerService();
                services.Configure<TelemetryConfiguration>(config => config.TelemetryChannel = channel);

                _ = services.AddLogging(builder =>
                {
                    builder.SetMinimumLevel(LogLevel.Information);
                    builder.AddFilter<ApplicationInsightsLoggerProvider>(typeof(SmartCardCertAdapter).FullName, LogLevel.Information);

                    builder.AddApplicationInsights(
                        configureTelemetryConfiguration: (config) => config.ConnectionString = connstr,
                        configureApplicationInsightsLoggerOptions: (options) => { }
                    );

                    builder.AddEventLog(new EventLogSettings
                    {
                        LogName = _logName,
                        SourceName = _sourceName,
                    });
                });

                IServiceProvider serviceProvider = services.BuildServiceProvider();

                ILogger<SmartCardCertAdapter> logger = serviceProvider.GetRequiredService<ILogger<SmartCardCertAdapter>>();
                telemetryClient = serviceProvider.GetRequiredService<TelemetryClient>();


                var requestTelemetry = new RequestTelemetry { Name = string.IsNullOrEmpty(appname) ? "ADFS Federal SmartCard Auth" : appname };



                //So long as the telemetry client is created and the operation is started in the factory, it will be able to track the request telemetry even outside of the factory
                var operation = telemetryClient.StartOperation(requestTelemetry);

                return logger;
            }
            catch (Exception ex)
            {
                LogToADFSEventLog(900, EventLogEntryType.Error, $"Message: {ex.Message}, Stacktrace: {ex.StackTrace}");
            }
            telemetryClient = null;
            return null;
        }

        public AppLogger(string connectionstring, string appname)
        {
            _connStr = connectionstring;
            _appName = appname;
            TelemetryClient teleclient;
            Logger = CreateLogger(channel, connectionstring, appname, out teleclient)
                ?? throw new InvalidOperationException("Logger creation failed.");
            TelemetryClientObj = teleclient
                ?? throw new InvalidOperationException("TelemetryClient creation failed.");
        }

        private static Dictionary<string, string> LogTraceProperties(string userlogin, string requetid, string appname, int eventid)
        {
            return new Dictionary<string, string>
            {
                {"EventId",eventid.ToString() },
                {"Application",appname },
                {"Login",userlogin },
                {"RequestId",requetid }
            };
        }

        public static Dictionary<string, object> LogTraceProperties(string userlogin, string requetid, string appname)
        {
            return new Dictionary<string, object>
            {
                {"Application",appname },
                {"Login",userlogin },
                {"RequestId",requetid }
            };
        }

        /// <summary>
        /// Log to with the following parameters.
        /// </summary>
        /// <param name="eventId"></param>
        /// <param name="entryType"></param>
        /// <param name="message"></param>
        public void LogIT(int eventId, EventLogEntryType entryType, string message)
        {
            if (Logger != null)
            {
                try
                {
                    switch (entryType)
                    {
                        case EventLogEntryType.Warning:
                            Logger.LogWarning(eventId, message); break;
                        case EventLogEntryType.Information:
                            Logger.LogInformation(eventId, message); break;
                        case EventLogEntryType.Error:
                            Logger.LogError(eventId, message); break;
                        default:
                            Logger.LogInformation(eventId, message); break;
                    }
                }
                catch (Exception ex)
                {
                    LogToADFSEventLog(900, EventLogEntryType.Error, $"Message: {ex.Message}, Stacktrace: {ex.StackTrace}");
                }
            }
            else
            {
                LogToADFSEventLog(eventId, entryType, message);
            }
        }

        /// <summary>
        /// Log with the following parameters.
        /// </summary>
        /// <param name="eventId"></param>
        /// <param name="entryType"></param>
        /// <param name="message"></param>
        /// <param name="traceid"></param>
        public void LogIT(int eventId, EventLogEntryType entryType, string message, string traceid)
        {
            try
            {
                LogIT(eventId, entryType, $"Message: {message}, RequestId: {traceid}");
            }
            catch (Exception ex)
            {
                LogToADFSEventLog(900, EventLogEntryType.Error, $"Message: {ex.Message}, Stacktrace: {ex.StackTrace}, RequestId: {traceid}");
            }
        }


        public void LogIT(int eventId, EventLogEntryType entryType, string message, string login, string traceid)
        {
            try
            {
                LogToADFSEventLog(eventId, entryType, $"Message: {message}, UserLogin: {login} RequestId: {traceid}");
                switch (entryType)
                {
                    case EventLogEntryType.Warning:
                        TelemetryClientObj.TrackTrace(message, SeverityLevel.Warning, LogTraceProperties(login, traceid, _appName, eventId)); break;
                    case EventLogEntryType.Information:
                        TelemetryClientObj.TrackTrace(message, SeverityLevel.Information, LogTraceProperties(login, traceid, _appName, eventId)); break;
                    case EventLogEntryType.Error:
                        TelemetryClientObj.TrackTrace(message, SeverityLevel.Error, LogTraceProperties(login, traceid, _appName, eventId)); break;
                    default:
                        TelemetryClientObj.TrackTrace(message, SeverityLevel.Verbose, LogTraceProperties(login, traceid, _appName, eventId)); break;
                }

            }
            catch (Exception ex)
            {
                LogToADFSEventLog(900, EventLogEntryType.Error, $"Message: {ex.Message}, Stacktrace: {ex.StackTrace}, RequestId: {traceid}");
            }
        }

        public static void LogToADFSEventLog(int eventId, EventLogEntryType entryType, string message)
        {
            try
            {

                EventLog eventLog = new EventLog(_logName, Environment.MachineName, _sourceName);

                // Write the entry to the ADFS event log
                eventLog.WriteEntry(message, entryType, eventId);
            }
            catch (Exception ex)
            {
                // Handle or log any exception that occurs during logging
                throw new Exception(ex.Message, ex);
            }
        }

        public static void LogDebug(bool debugEnabled, string message)
        {
            if (debugEnabled)
            {
                LogToADFSEventLog(200, EventLogEntryType.Information, message);
            }
        }

        void IDisposable.Dispose()
        {
            // Flush the channel to ensure that all messages are sent
            channel.Flush();
            channel.Dispose();

            Task.Delay(1000).Wait();
        }
    }
}
