using DotCruz.Shared.Security.Authentication.ApiKey;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class UserAndServicePolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, ServiceApiKeyDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim(ClaimTypes.Sid)
            .RequireClaim("service_identity", "true")
            .Build();
    }
}
