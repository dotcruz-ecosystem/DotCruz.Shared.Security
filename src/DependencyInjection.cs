using DotCruz.Shared.Security.Authorization;
using DotCruz.Shared.Security.Context;
using DotCruz.Shared.Security.Extensions;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DotCruz.Shared.Security;

public static class DependencyInjection
{
    public static IServiceCollection AddSharedSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddScoped<ISecurityContext, SecurityContext>();

        services.AddSharedAuthentication(configuration);
        services.AddSharedAuthorization();

        services.TryAddEnumerable(
            ServiceDescriptor.Transient<IActionDescriptorProvider, AuthorizeOverrideActionDescriptorProvider>());

        return services;
    }
}
