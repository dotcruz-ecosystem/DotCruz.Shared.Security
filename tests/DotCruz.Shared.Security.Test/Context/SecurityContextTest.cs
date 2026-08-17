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
    public void TenantId_Comes_From_Claim_For_Authenticated_User()
    {
        var tenantId = Guid.NewGuid();
        var context = BuildUser(tenantId: tenantId);

        Assert.Equal(tenantId, context.TenantId);
    }

    [Fact]
    public void TenantId_Ignores_Header_When_Caller_Is_A_User()
    {
        var headerTenantId = Guid.NewGuid();
        var context = BuildUser(tenantId: null, headerTenantId: headerTenantId);

        Assert.Null(context.TenantId);
    }

    [Fact]
    public void TenantId_Prefers_Claim_Over_Header_For_A_User()
    {
        var claimTenantId = Guid.NewGuid();
        var context = BuildUser(tenantId: claimTenantId, headerTenantId: Guid.NewGuid());

        Assert.Equal(claimTenantId, context.TenantId);
    }

    [Fact]
    public void TenantId_Ignores_Header_When_Caller_Is_Anonymous()
    {
        var context = BuildAnonymous(headerTenantId: Guid.NewGuid());

        Assert.Null(context.TenantId);
    }

    [Fact]
    public void TenantId_Comes_From_Header_For_Authenticated_Service()
    {
        var headerTenantId = Guid.NewGuid();
        var context = BuildService(headerTenantId: headerTenantId);

        Assert.Equal(headerTenantId, context.TenantId);
    }

    [Fact]
    public void TenantId_Is_Null_For_Service_Without_Header()
    {
        var context = BuildService(headerTenantId: null);

        Assert.Null(context.TenantId);
    }

    [Fact]
    public void IsAuthenticatedService_Requires_The_Service_Identity_Claim()
    {
        Assert.True(BuildService(null).IsAuthenticatedService);
        Assert.False(BuildUser(Guid.NewGuid()).IsAuthenticatedService);
        Assert.False(BuildAnonymous(null).IsAuthenticatedService);
    }

    private static ISecurityContext BuildUser(Guid? tenantId, Guid? headerTenantId = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.Sid, Guid.NewGuid().ToString()) };

        if (tenantId.HasValue)
            claims.Add(new Claim(CustomClaimsTypes.TenantId, tenantId.Value.ToString()));

        return Build(new ClaimsIdentity(claims, JwtScheme), headerTenantId);
    }

    private static ISecurityContext BuildService(Guid? headerTenantId)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "test-service"),
            new(CustomClaimsTypes.ServiceIdentity, "true")
        };

        return Build(new ClaimsIdentity(claims, ApiKeyScheme), headerTenantId);
    }

    private static ISecurityContext BuildAnonymous(Guid? headerTenantId) =>
        Build(new ClaimsIdentity(), headerTenantId);

    private static ISecurityContext Build(ClaimsIdentity identity, Guid? headerTenantId)
    {
        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity)
        };

        if (headerTenantId.HasValue)
            httpContext.Request.Headers["X-Tenant-ID"] = headerTenantId.Value.ToString();

        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(httpContext);

        return new SecurityContext(accessor.Object);
    }
}
