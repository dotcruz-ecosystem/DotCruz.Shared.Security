using DotCruz.Shared.Security.Authentication.ApiKey;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceApiKeyHttpClientExtensions
{
    public static IHttpClientBuilder AddServiceApiKeyPropagation(this IHttpClientBuilder builder)
    {
        builder.AddHttpMessageHandler<ServiceApiKeyHttpClientHandler>();
        return builder;
    }
}
