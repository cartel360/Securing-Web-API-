using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SecuringWebApiUsingApiKey.Attributes
{
   // Decoration to indicats and specifies where the Api Key will be used i.e on classes like controllers
   [AttributeUsage(validOn: AttributeTargets.Class)]
    public class ApiKeyAttribute: Attribute, IAsyncActionFilter
    {
       private const string APIKEYNAME = "ApiKey";
       public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
       {
          if (!context.HttpContext.Request.Headers.TryGetValue(APIKEYNAME, out var extractedApiKey))
          {
             context.Result = new ContentResult()
             {
                StatusCode = 401,
                Content = "Api Key was not provided"
             };
             return;
          }

          var appSettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
          
          // Get Api Key from appsettings.json
          var apiKey = appSettings.GetValue<string>("ApiKey");

          if(!apiKey.Equals(extractedApiKey))
          {
             context.Result = new ContentResult()
             {
                StatusCode = 401,
                Content = "Api Key is invalid"
             };
             return;
          }

          await next();
       }
    }
}
