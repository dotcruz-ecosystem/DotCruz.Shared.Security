using DotCruz.Shared.Security.Context;
using DotCruz.Shared.Security.CustomClaim;
using Microsoft.AspNetCore.Http;
using Moq;
using System.Security.Claims;

namespace DotCruz.Shared.Security.Test.Context;

public class SecurityContextTest
{
    private const string ApiKeyScheme = "ServiceApiKey";
    private const string JwtScheme = "Bearer";

    [Fact]
    public void WorkspaceId_Comes_From_Claim_For_Authenticated_User()
    {
        var workspaceId = Guid.NewGuid();
        var context = BuildUser(workspaceId: workspaceId);

        Assert.Equal(workspaceId, context.WorkspaceId);
    }

    [Fact]
    public void WorkspaceId_Ignores_Header_When_Caller_Is_A_User()
    {
        var headerWorkspaceId = Guid.NewGuid();
        var context = BuildUser(workspaceId: null, headerWorkspaceId: headerWorkspaceId);

        Assert.Null(context.WorkspaceId);
    }

    [Fact]
    public void WorkspaceId_Prefers_Claim_Over_Header_For_A_User()
    {
        var claimWorkspaceId = Guid.NewGuid();
        var context = BuildUser(workspaceId: claimWorkspaceId, headerWorkspaceId: Guid.NewGuid());

        Assert.Equal(claimWorkspaceId, context.WorkspaceId);
    }

    [Fact]
    public void WorkspaceId_Ignores_Header_When_Caller_Is_Anonymous()
    {
        var context = BuildAnonymous(headerWorkspaceId: Guid.NewGuid());

        Assert.Null(context.WorkspaceId);
    }

    [Fact]
    public void WorkspaceId_Comes_From_Header_For_Authenticated_Service()
    {
        var headerWorkspaceId = Guid.NewGuid();
        var context = BuildService(headerWorkspaceId: headerWorkspaceId);

        Assert.Equal(headerWorkspaceId, context.WorkspaceId);
    }

    [Fact]
    public void WorkspaceId_Is_Null_For_Service_Without_Header()
    {
        var context = BuildService(headerWorkspaceId: null);

        Assert.Null(context.WorkspaceId);
    }

    [Fact]
    public void IsAuthenticatedService_Requires_The_Service_Identity_Claim()
    {
        Assert.True(BuildService(null).IsAuthenticatedService);
        Assert.False(BuildUser(Guid.NewGuid()).IsAuthenticatedService);
        Assert.False(BuildAnonymous(null).IsAuthenticatedService);
    }

    private static ISecurityContext BuildUser(Guid? workspaceId, Guid? headerWorkspaceId = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.Sid, Guid.NewGuid().ToString()) };

        if (workspaceId.HasValue)
            claims.Add(new Claim(CustomClaimsTypes.WorkspaceId, workspaceId.Value.ToString()));

        return Build(new ClaimsIdentity(claims, JwtScheme), headerWorkspaceId);
    }

    private static ISecurityContext BuildService(Guid? headerWorkspaceId)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "test-service"),
            new(CustomClaimsTypes.ServiceIdentity, "true")
        };

        return Build(new ClaimsIdentity(claims, ApiKeyScheme), headerWorkspaceId);
    }

    private static ISecurityContext BuildAnonymous(Guid? headerWorkspaceId) =>
        Build(new ClaimsIdentity(), headerWorkspaceId);

    private static ISecurityContext Build(ClaimsIdentity identity, Guid? headerWorkspaceId)
    {
        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity)
        };

        if (headerWorkspaceId.HasValue)
            httpContext.Request.Headers["X-Workspace-ID"] = headerWorkspaceId.Value.ToString();

        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(httpContext);

        return new SecurityContext(accessor.Object);
    }
}
