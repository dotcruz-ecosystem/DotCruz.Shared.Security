using DotCruz.Shared.Security.Authentication.ApiKey;
using DotCruz.Shared.Security.CustomClaim;
using Microsoft.AspNetCore.Authorization;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class ServiceOnlyPolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(ServiceApiKeyDefaults.AuthenticationScheme)
            .RequireClaim(CustomClaimsTypes.ServiceIdentity, "true")
            .Build();
    }
}
