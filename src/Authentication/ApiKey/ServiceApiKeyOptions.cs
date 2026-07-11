using Microsoft.AspNetCore.Authentication;

namespace DotCruz.Shared.Security.Authentication.ApiKey;

public class ServiceApiKeyOptions : AuthenticationSchemeOptions
{
    public Dictionary<string, string> Keys { get; set; } = new();
}
