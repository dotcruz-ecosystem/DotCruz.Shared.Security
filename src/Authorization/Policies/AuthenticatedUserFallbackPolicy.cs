using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class AuthenticatedUserFallbackPolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .Build();
    }
}
