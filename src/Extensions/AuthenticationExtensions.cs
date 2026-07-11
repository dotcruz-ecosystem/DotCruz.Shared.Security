using DotCruz.Shared.Security.Authentication.ApiKey;
using DotCruz.Shared.Security.Authentication.Jwt;
using DotCruz.Shared.Security.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace DotCruz.Shared.Security.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddSharedAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var jwtSettings = configuration.GetSection("Settings:Jwt").Get<JwtSettings>();

        if (jwtSettings == null || !jwtSettings.IsValid)
            throw new InvalidOperationException(DotCruz.Shared.Security.Resources.SecurityResources.CriticalJwtConfigMissing);

        var selfServiceAuthSettings = configuration.GetSection("Settings:ServiceAuth:Self").Get<SelfServiceAuthSettings>();

        if (selfServiceAuthSettings == null || !selfServiceAuthSettings.IsValid)
            throw new InvalidOperationException(DotCruz.Shared.Security.Resources.SecurityResources.CriticalServiceAuthConfigMissing);

        services.Configure<ServiceAuthSelfOptions>(configuration.GetSection("Settings:ServiceAuth:Self"));
        services.AddTransient<ServiceApiKeyHttpClientHandler>();

        services.AddSingleton<IJwksKeyResolver>(new JwksKeyResolver(jwtSettings.JwksUrl));

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, null!)
        .AddScheme<ServiceApiKeyOptions, ServiceApiKeyHandler>(ServiceApiKeyDefaults.AuthenticationScheme, _ => { });

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IJwksKeyResolver>((options, resolver) =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                    {
                        return resolver.GetSigningKeysAsync().GetAwaiter().GetResult();
                    }
                };
            });

        services.AddOptions<ServiceApiKeyOptions>(ServiceApiKeyDefaults.AuthenticationScheme)
            .Configure<IConfiguration>((options, config) =>
            {
                config.GetSection("Settings:ServiceAuth:Keys").Bind(options.Keys);
            });

        return services;
    }
}
