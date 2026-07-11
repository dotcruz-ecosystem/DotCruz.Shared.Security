using DotCruz.Shared.Security.Authentication.ApiKey;
using Microsoft.AspNetCore.Authorization;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class ServiceOnlyPolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(ServiceApiKeyDefaults.AuthenticationScheme)
            .RequireClaim("service_identity", "true")
            .Build();
    }
}
