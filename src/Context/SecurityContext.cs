using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace DotCruz.Shared.Security.Context;

public class SecurityContext(IHttpContextAccessor httpContextAccessor) : ISecurityContext
{
    private const string TenantIdClaimType = "tenant_id";
    private const string TenantIdClaimTypeAlternative = "TenantId";

    public Guid? UserId
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            if (user == null) return null;

            var userIdStr = user.FindFirst(ClaimTypes.Sid)?.Value 
                            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                            ?? user.FindFirst("sub")?.Value;

            return Guid.TryParse(userIdStr, out var userId) ? userId : null;
        }
    }

    public Guid? TenantId
    {
        get
        {
            var httpContext = httpContextAccessor.HttpContext;
            if (httpContext == null) return null;

            var tenantClaim = httpContext.User?.FindFirst(TenantIdClaimType)?.Value 
                              ?? httpContext.User?.FindFirst(TenantIdClaimTypeAlternative)?.Value;

            if (Guid.TryParse(tenantClaim, out var tenantId))
                return tenantId;

            if (httpContext.Request.Headers.TryGetValue("X-Tenant-ID", out var tenantHeader))
            {
                if (Guid.TryParse(tenantHeader.ToString(), out var parsedId))
                    return parsedId;
            }

            return null;
        }
    }

    public string? ServiceName => httpContextAccessor.HttpContext?.User?.FindFirst(ClaimTypes.Name)?.Value;

    public IEnumerable<string> Roles
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            
            if (user == null) 
                return [];

            return Enumerable.Distinct(
                Enumerable.Concat(
                    Enumerable.Select(user.FindAll(ClaimTypes.Role), c => c.Value),
                    Enumerable.Select(user.FindAll("role"), c => c.Value)
                )
            );
        }
    }

    public bool IsAuthenticatedUser
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            var identity = user?.Identity;
            return identity != null && identity.IsAuthenticated && UserId.HasValue;
        }
    }

    public bool IsAuthenticatedService
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            return user != null && user.Identity?.IsAuthenticated == true && user.HasClaim("service_identity", "true");
        }
    }
}
