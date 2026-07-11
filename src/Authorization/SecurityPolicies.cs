namespace DotCruz.Shared.Security.Authorization;

public static class SecurityPolicies
{
    public const string UserOnly = "UserOnly";
    public const string ServiceOnly = "ServiceOnly";
    public const string UserAndService = "UserAndService";
    public const string UserOrService = "UserOrService";
    public const string AdminOnly = "AdminOnly";
    public const string TenantAdminOrAdmin = "TenantAdminOrAdmin";
    public const string AnyUser = "AnyUser";
}
