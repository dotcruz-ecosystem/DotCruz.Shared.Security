using DotCruz.Shared.Security.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace DotCruz.Shared.Security.Observability;

public class AuditLogMiddleware(
    RequestDelegate next, 
    ILogger<AuditLogMiddleware> logger
)
{
    public async Task InvokeAsync(HttpContext context, ISecurityContext securityContext)
    {
        await next(context);

        var userId = securityContext.UserId;
        var serviceName = securityContext.ServiceName;
        var workspaceId = securityContext.WorkspaceId;
        var httpMethod = context.Request.Method;
        var path = context.Request.Path;
        var statusCode = context.Response.StatusCode;

        logger.LogInformation(
            DotCruz.Shared.Security.Resources.SecurityResources.AuditLogMessage,
            userId, serviceName, workspaceId, httpMethod, path, statusCode
        );
    }
}
