using System.Net.Http.Headers;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;

var configuration = TokenAcquirerFactory.GetDefaultInstance().Configuration;

var clientId = configuration["AzureAd:ClientId"]
    ?? throw new InvalidOperationException("AzureAd:ClientId is not configured.");
var authority = configuration["AzureAd:Authority"]
    ?? throw new InvalidOperationException("AzureAd:Authority is not configured.");
var clientSecret = Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET")
    ?? throw new InvalidOperationException("Set the AZURE_CLIENT_SECRET environment variable.");
var scopes = configuration.GetSection("DownstreamApi:Scopes").Get<string[]>()
    ?? throw new InvalidOperationException("DownstreamApi:Scopes are not configured.");
var baseUrl = configuration["DownstreamApi:BaseUrl"]
    ?? throw new InvalidOperationException("DownstreamApi:BaseUrl is not configured.");
var relativePath = configuration["DownstreamApi:RelativePath"]
    ?? throw new InvalidOperationException("DownstreamApi:RelativePath is not configured.");

var app = ConfidentialClientApplicationBuilder
    .Create(clientId)
    .WithAuthority(authority)
    .WithClientSecret(clientSecret)
    .Build();

var token = await app.AcquireTokenForClient(scopes).ExecuteAsync();

var claims = System.Text.Json.JsonDocument.Parse(
    Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(token.AccessToken.Split('.')[1])).RootElement;
foreach (var name in new[] { "aud", "iss", "tid", "ver", "roles", "scp" })
{
    if (claims.TryGetProperty(name, out var value))
    {
        Console.WriteLine($"Token {name}: {value}");
    }
}
var requestUri = new Uri(new Uri(baseUrl), relativePath.TrimStart('/'));

using var client = new HttpClient();
client.DefaultRequestHeaders.Authorization =
    new AuthenticationHeaderValue("Bearer", token.AccessToken);

using var response = await client.GetAsync(requestUri);
var content = await response.Content.ReadAsStringAsync();

Console.WriteLine("Your response is: " + response.StatusCode);
Console.WriteLine(content);

if (!response.IsSuccessStatusCode)
{
    foreach (var challenge in response.Headers.WwwAuthenticate)
    {
        Console.WriteLine("WWW-Authenticate: " + challenge);
    }
}
