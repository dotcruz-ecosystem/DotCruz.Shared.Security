using DotCruz.Shared.Security.Authentication.ApiKey;
using DotCruz.Shared.Security.CustomClaim;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace DotCruz.Shared.Security.Authorization.Policies;

public static class UserOrServicePolicy
{
    public static AuthorizationPolicy Build()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, ServiceApiKeyDefaults.AuthenticationScheme)
            .RequireAssertion(context =>
                context.User.HasClaim(c => c.Type == ClaimTypes.Sid) ||
                context.User.HasClaim(c => c.Type == CustomClaimsTypes.ServiceIdentity && c.Value == "true")
            )
            .Build();
    }
}
