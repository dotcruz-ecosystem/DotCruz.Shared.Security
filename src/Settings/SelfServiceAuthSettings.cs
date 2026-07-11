namespace DotCruz.Shared.Security.Settings;

public class SelfServiceAuthSettings
{
    public string Name { get; set; } = string.Empty;
    public string Key { get; set; } = string.Empty;

    public bool IsValid => !string.IsNullOrWhiteSpace(Name) &&
                           !string.IsNullOrWhiteSpace(Key);
}
