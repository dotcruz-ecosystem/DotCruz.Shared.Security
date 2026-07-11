# DotCruz.Shared.Security

Pacote de segurança oficial contendo utilitários de autenticação, autorização, auditoria e propagação de contexto de multi-tenancy para a plataforma DotCruz.

## Instalação

Você pode instalar o pacote via NuGet CLI:

```bash
dotnet add package DotCruz.Shared.Security
```

Ou via Gerenciador de Pacotes do Visual Studio procurando por `DotCruz.Shared.Security`.

## Conteúdo do Pacote

### Autenticação e Autorização
- **AddSharedSecurity**: Método de extensão unificado para configuração de autenticação JWT Bearer (JWKS/Chave assimétrica) e autenticação M2M baseada em API Key.
- **ApiKey**: Handlers e validadores para autenticação baseada em chaves de serviço.

### Contexto de Segurança
- **ISecurityContext**: Interface injetável que fornece acesso seguro aos dados do usuário/serviço autenticado na requisição atual:
  - `UserId`: ID do usuário autenticado.
  - `TenantId`: ID do Tenant ativo (resolvido via claims ou cabeçalho `X-Tenant-ID`).
  - `Roles`: Funções atribuídas ao usuário.
  - `IsAuthenticatedUser`: Indica se a chamada é de um usuário final autenticado.
  - `IsAuthenticatedService`: Indica se a chamada é de integração de serviços (M2M) autenticada.

### Observabilidade
- **AuditLogMiddleware**: Middleware integrado para gravação de logs de auditoria detalhados de requisições HTTP (usuário, serviço, tenant, método, endpoint e status de retorno).

### Propagação de Contexto
- **AddServiceApiKeyPropagation**: Extensão para `IHttpClientBuilder` que registra automaticamente o `ServiceApiKeyHttpClientHandler`, propagando a chave de API do serviço e o cabeçalho `X-Tenant-ID` da requisição atual para chamadas HTTP de saída.

---

## Exemplo de Uso

### 1. Registro e Configuração no Startup (`Program.cs`)

```csharp
using DotCruz.Shared.Security;

var builder = WebApplication.CreateBuilder(args);

// Adiciona os serviços de segurança da biblioteca
builder.Services.AddSharedSecurity(builder.Configuration);

var app = builder.Build();

// Habilita o log de auditoria no pipeline (deve ser registrado antes da autenticação)
app.UseSharedSecurityAuditLog();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

### 2. Configurando a Propagação em HttpClients

Para propagar a segurança e o `TenantId` em chamadas para outros microsserviços do ecossistema:

```csharp
using DotCruz.Shared.Security;

builder.Services.AddHttpClient<ICoreAuthClient, CoreAuthClient>(client =>
{
    client.BaseAddress = new Uri("http://dotcruz-coreauth-api:8080/");
})
.AddServiceApiKeyPropagation();
```

### 3. Utilizando o Contexto de Segurança nas Classes de Negócio

```csharp
using DotCruz.Shared.Security.Context;

public class CustomService(ISecurityContext securityContext)
{
    public void ExecutarAcao()
    {
        var tenantId = securityContext.TenantId;
        var userId = securityContext.UserId;
        
        if (securityContext.IsAuthenticatedService)
        {
            var serviceName = securityContext.ServiceName;
            // Lógica para chamada vinda de outro microsserviço
        }
    }
}
```
