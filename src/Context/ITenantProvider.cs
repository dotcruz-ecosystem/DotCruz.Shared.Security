namespace DotCruz.Shared.Security.Context;

public interface ITenantProvider
{
    Guid? TenantId { get; }
    Guid? UserId { get; }
    string? TenantType { get; }
    string? TenantPlan { get; }
    bool FilterByUserId { get; }
}
