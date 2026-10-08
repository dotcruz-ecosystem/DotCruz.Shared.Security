namespace DotCruz.Shared.Security.Context;

public interface IWorkspaceProvider
{
    Guid? WorkspaceId { get; }
    Guid? UserId { get; }
    string? WorkspaceType { get; }
    string? WorkspacePlan { get; }
    bool FilterByUserId { get; }
}
