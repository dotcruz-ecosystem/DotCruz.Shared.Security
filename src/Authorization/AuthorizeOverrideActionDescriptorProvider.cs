using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

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
                    var actionAuthAttributes = controllerActionDescriptor.MethodInfo
                        .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                        .OfType<AuthorizeAttribute>()
                        .ToList();

                    var controllerAuthAttributes = controllerActionDescriptor.ControllerTypeInfo
                        .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                        .OfType<AuthorizeAttribute>()
                        .ToList();

                    var baseAuthAttributes = new List<AuthorizeAttribute>();
                    var currentBaseType = controllerActionDescriptor.ControllerTypeInfo.BaseType;
                    while (currentBaseType != null && currentBaseType != typeof(object))
                    {
                        var attrs = currentBaseType.GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                            .OfType<AuthorizeAttribute>();
                        baseAuthAttributes.AddRange(attrs);
                        currentBaseType = currentBaseType.BaseType;
                    }

                    List<AuthorizeAttribute> activeAttributes;

                    if (actionAuthAttributes.Count != 0)
                    {
                        activeAttributes = actionAuthAttributes;
                    }
                    else if (controllerAuthAttributes.Count != 0)
                    {
                        activeAttributes = controllerAuthAttributes;
                    }
                    else
                    {
                        activeAttributes = baseAuthAttributes;
                    }

                    if (actionAuthAttributes.Count != 0 || controllerAuthAttributes.Count != 0 || baseAuthAttributes.Count != 0)
                    {
                        for (var i = descriptor.EndpointMetadata.Count - 1; i >= 0; i--)
                        {
                            if (descriptor.EndpointMetadata[i] is IAuthorizeData)
                            {
                                descriptor.EndpointMetadata.RemoveAt(i);
                            }
                        }

                        foreach (var activeAttr in activeAttributes)
                        {
                            descriptor.EndpointMetadata.Add(activeAttr);
                        }

                        for (var i = descriptor.FilterDescriptors.Count - 1; i >= 0; i--)
                        {
                            var filterDescriptor = descriptor.FilterDescriptors[i];
                            if (filterDescriptor.Filter is AuthorizeFilter &&
                                (filterDescriptor.Scope == FilterScope.Controller || filterDescriptor.Scope == FilterScope.Action))
                            {
                                descriptor.FilterDescriptors.RemoveAt(i);
                            }
                        }

                        foreach (var activeAttr in activeAttributes)
                        {
                            descriptor.FilterDescriptors.Add(new FilterDescriptor(
                                new AuthorizeFilter([activeAttr]),
                                FilterScope.Action
                            ));
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
