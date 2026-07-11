namespace DotCruz.Shared.Security.Settings;

public class JwtSettings
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string JwksUrl { get; set; } = string.Empty;

    public bool IsValid =>  !string.IsNullOrWhiteSpace(Issuer) && 
                            !string.IsNullOrWhiteSpace(Audience) && 
                            !string.IsNullOrWhiteSpace(JwksUrl);
}

