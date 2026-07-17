using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using System.Linq;

namespace DotCruz.Shared.Security.Authorization
{
    public class AuthorizeOverrideConvention : IActionModelConvention
    {
        public void Apply(ActionModel action)
        {
            var hasActionAuthorize = action.Attributes.OfType<AuthorizeAttribute>().Any();

            if (hasActionAuthorize)
            {
                foreach (var selector in action.Selectors)
                {
                    var controllerAuthAttributes = action.Controller.Attributes.OfType<AuthorizeAttribute>().ToList();
                    
                    foreach (var controllerAttr in controllerAuthAttributes)
                    {
                        selector.EndpointMetadata.Remove(controllerAttr);
                    }
                }
            }
        }
    }
}
