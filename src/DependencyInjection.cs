using DotCruz.Shared.Security.Authorization;
using DotCruz.Shared.Security.Context;
using DotCruz.Shared.Security.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DotCruz.Shared.Security;

public static class DependencyInjection
{
    public static IServiceCollection AddSharedSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddScoped<ISecurityContext, SecurityContext>();

        services.AddSharedAuthentication(configuration);
        services.AddSharedAuthorization();

        services.Configure<MvcOptions>(options => options.Conventions.Add(new AuthorizeOverrideConvention()));

        return services;
    }
}
