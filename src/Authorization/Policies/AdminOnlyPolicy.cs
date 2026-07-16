using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class AdminOnlyPolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
            .RequireRole("SuperAdmin")
            .Build();
    }
}
