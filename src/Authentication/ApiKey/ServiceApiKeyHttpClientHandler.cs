using Microsoft.Extensions.Options;
using DotCruz.Shared.Security.Context;

namespace DotCruz.Shared.Security.Authentication.ApiKey;

public class ServiceApiKeyHttpClientHandler : DelegatingHandler
{
    private readonly ServiceAuthSelfOptions _selfOptions;
    private readonly ISecurityContext _securityContext;

    public ServiceApiKeyHttpClientHandler(
        IOptions<ServiceAuthSelfOptions> selfOptions,
        ISecurityContext securityContext)
    {
        _selfOptions = selfOptions.Value;
        _securityContext = securityContext;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Remove("X-Api-Key");
        request.Headers.Remove("X-Service-Name");

        request.Headers.Add("X-Api-Key", _selfOptions.Key);
        request.Headers.Add("X-Service-Name", _selfOptions.Name);

        var tenantId = _securityContext.TenantId;
        if (tenantId.HasValue)
        {
            request.Headers.Remove("X-Tenant-ID");
            request.Headers.Add("X-Tenant-ID", tenantId.Value.ToString());
        }

        return base.SendAsync(request, cancellationToken);
    }
}
