using DotCruz.Shared.Security.Authorization;
using DotCruz.Shared.Security.Authorization.Policies;
using Microsoft.Extensions.DependencyInjection;

namespace DotCruz.Shared.Security.Extensions;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddSharedAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(SecurityPolicies.UserOnly, UserOnlyPolicy.Build())
            .AddPolicy(SecurityPolicies.ServiceOnly, ServiceOnlyPolicy.Build())
            .AddPolicy(SecurityPolicies.UserAndService, UserAndServicePolicy.Build())
            .AddPolicy(SecurityPolicies.UserOrService, UserOrServicePolicy.Build())
            .AddPolicy(SecurityPolicies.AdminOnly, AdminOnlyPolicy.Build())
            .AddPolicy(SecurityPolicies.TenantAdminOrAdmin, TenantAdminOrAdminPolicy.Build())
            .AddPolicy(SecurityPolicies.AnyUser, AnyUserPolicy.Build());

        return services;
    }
}
