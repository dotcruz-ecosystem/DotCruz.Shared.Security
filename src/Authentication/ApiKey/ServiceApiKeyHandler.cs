using DotCruz.Shared.Security.CustomClaim;
using DotCruz.Shared.Security.Resources;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace DotCruz.Shared.Security.Authentication.ApiKey;

public class ServiceApiKeyHandler : AuthenticationHandler<ServiceApiKeyOptions>
{
    private const string ApiKeyHeaderName = "X-Api-Key";
    private const string ServiceNameHeaderName = "X-Service-Name";

    public ServiceApiKeyHandler(
        IOptionsMonitor<ServiceApiKeyOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ServiceNameHeaderName, out var serviceNameValues) ||
            string.IsNullOrWhiteSpace(serviceNameValues.ToString()))
        {
            return Task.FromResult(AuthenticateResult.Fail(SecurityResources.ServiceNameMissing));
        }

        var serviceName = serviceNameValues.ToString();

        if (!Request.Headers.TryGetValue(ApiKeyHeaderName, out var apiKeyHeaderValues))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var providedApiKey = apiKeyHeaderValues.ToString();
        if (string.IsNullOrWhiteSpace(providedApiKey))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!Options.Keys.TryGetValue(serviceName, out var expectedApiKey) ||
            string.IsNullOrWhiteSpace(expectedApiKey))
        {
            return Task.FromResult(AuthenticateResult.Fail(string.Format(SecurityResources.ServiceNotAuthorized, serviceName)));
        }

        var providedBytes = Encoding.UTF8.GetBytes(providedApiKey);
        var expectedBytes = Encoding.UTF8.GetBytes(expectedApiKey);

        if (!CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes))
        {
            return Task.FromResult(AuthenticateResult.Fail(SecurityResources.InvalidApiKey));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, serviceName),
            new Claim(CustomClaimsTypes.ServiceIdentity, "true")
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
