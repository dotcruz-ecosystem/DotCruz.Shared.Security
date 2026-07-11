using DotCruz.Shared.Security.Observability;
using Microsoft.AspNetCore.Builder;

namespace Microsoft.AspNetCore.Builder;

public static class ApplicationExtensions
{
    public static IApplicationBuilder UseSharedSecurityAuditLog(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AuditLogMiddleware>();
    }
}
