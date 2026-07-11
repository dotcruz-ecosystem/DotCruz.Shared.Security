namespace DotCruz.Shared.Security.Context;

public interface ISecurityContext
{
    Guid? UserId { get; }
    Guid? TenantId { get; }
    string? ServiceName { get; }
    IEnumerable<string> Roles { get; }
    bool IsAuthenticatedUser { get; }
    bool IsAuthenticatedService { get; }
}
