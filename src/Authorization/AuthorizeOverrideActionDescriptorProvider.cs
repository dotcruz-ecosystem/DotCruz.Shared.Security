using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace DotCruz.Shared.Security.Authorization
{
    public class AuthorizeOverrideActionDescriptorProvider : IActionDescriptorProvider
    {
        public int Order => 0;

        public void OnProvidersExecuting(ActionDescriptorProviderContext context)
        {
            foreach (var descriptor in context.Results)
            {
                if (descriptor is ControllerActionDescriptor controllerActionDescriptor)
                {
                    var hasActionAuthorize = controllerActionDescriptor.MethodInfo
                        .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                        .Any();

                    if (hasActionAuthorize)
                    {
                        var actionAuthAttributes = controllerActionDescriptor.MethodInfo
                            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                            .Cast<IAuthorizeData>()
                            .ToList();

                        for (var i = descriptor.EndpointMetadata.Count - 1; i >= 0; i--)
                        {
                            if (descriptor.EndpointMetadata[i] is IAuthorizeData)
                            {
                                descriptor.EndpointMetadata.RemoveAt(i);
                            }
                        }

                        foreach (var actionAuth in actionAuthAttributes)
                        {
                            descriptor.EndpointMetadata.Add(actionAuth);
                        }
                    }
                }
            }
        }

        public void OnProvidersExecuted(ActionDescriptorProviderContext context)
        {
        }
    }
}
