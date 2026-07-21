using DotCruz.Shared.Security.CustomClaim;
using Microsoft.AspNetCore.Http;

namespace DotCruz.Shared.Security.Context;

public class TenantProvider(ISecurityContext securityContext, IHttpContextAccessor httpContextAccessor) : ITenantProvider
{
    public Guid? TenantId => securityContext.TenantId;
    public Guid? UserId => securityContext.UserId;

    public string? TenantType => httpContextAccessor.HttpContext?.User?.FindFirst(CustomClaimsTypes.TenantType)?.Value;
    public string? TenantPlan => httpContextAccessor.HttpContext?.User?.FindFirst(CustomClaimsTypes.TenantPlan)?.Value;

    public bool FilterByUserId
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            if (user == null) return true;

            if (string.Equals(TenantType, "Enterprise", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(TenantPlan, "Enterprise", StringComparison.OrdinalIgnoreCase) ||
                securityContext.Roles.Contains("EnterpriseMember"))
            {
                return false;
            }

            return true;
        }
    }
}
