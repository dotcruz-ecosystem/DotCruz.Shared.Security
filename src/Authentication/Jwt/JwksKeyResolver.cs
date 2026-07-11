using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace DotCruz.Shared.Security.Authentication.Jwt;

public interface IJwksKeyResolver
{
    Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(CancellationToken cancellationToken = default);
}

public class JwksKeyResolver : IJwksKeyResolver
{
    private readonly ConfigurationManager<JsonWebKeySet> _configurationManager;

    public JwksKeyResolver(string jwksUrl)
    {
        if (string.IsNullOrWhiteSpace(jwksUrl))
            throw new ArgumentException("JWKS URL cannot be null or empty.", nameof(jwksUrl));

        var documentRetriever = new HttpDocumentRetriever
        {
            RequireHttps = jwksUrl.StartsWith("https", StringComparison.OrdinalIgnoreCase)
        };

        _configurationManager = new ConfigurationManager<JsonWebKeySet>(
            jwksUrl,
            new JsonWebKeySetRetriever(),
            documentRetriever
        );
    }

    public async Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var jwks = await _configurationManager.GetConfigurationAsync(cancellationToken);
            return jwks.GetSigningKeys();
        }
        catch (Exception)
        {
            return [];
        }
    }

    private class JsonWebKeySetRetriever : IConfigurationRetriever<JsonWebKeySet>
    {
        public async Task<JsonWebKeySet> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancellationToken)
        {
            var doc = await retriever.GetDocumentAsync(address, cancellationToken);
            return new JsonWebKeySet(doc);
        }
    }
}
