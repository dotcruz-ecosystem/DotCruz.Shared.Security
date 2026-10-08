using DotCruz.Shared.Security.CustomClaim;
using Microsoft.AspNetCore.Http;

namespace DotCruz.Shared.Security.Context;

public class WorkspaceProvider(ISecurityContext securityContext, IHttpContextAccessor httpContextAccessor) : IWorkspaceProvider
{
    public Guid? WorkspaceId => securityContext.WorkspaceId;
    public Guid? UserId => securityContext.UserId;

    public string? WorkspaceType => httpContextAccessor.HttpContext?.User?.FindFirst(CustomClaimsTypes.WorkspaceType)?.Value;
    public string? WorkspacePlan => httpContextAccessor.HttpContext?.User?.FindFirst(CustomClaimsTypes.WorkspacePlan)?.Value;

    public bool FilterByUserId
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            if (user == null) return true;

            if (string.Equals(WorkspaceType, "Enterprise", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(WorkspacePlan, "Enterprise", StringComparison.OrdinalIgnoreCase) ||
                securityContext.Roles.Contains("EnterpriseMember"))
            {
                return false;
            }

            return true;
        }
    }
}
