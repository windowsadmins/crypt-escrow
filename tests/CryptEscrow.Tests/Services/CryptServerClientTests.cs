using System.Net;
using System.Net.Http;
using CryptEscrow.Services;
using FluentAssertions;
using RichardSzalay.MockHttp;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Covers <see cref="CryptServerClient"/> HTTP behavior via the internal
/// test constructor that accepts a <see cref="HttpMessageHandler"/>.
/// </summary>
public class CryptServerClientTests
{
    private const string BaseUrl = "https://crypt.test";

    private static CheckinRequest SampleCheckin() => new()
    {
        Serial = "SN-123",
        RecoveryPassword = "123456-789012-345678-901234-567890-123456-789012-345678",
        Username = "alice",
        MachineName = "TEST-PC",
    };

    // -------------------------- CheckinAsync ------------------------

    [Fact]
    public async Task CheckinAsync_Success_ReturnsParsedResponse()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .Respond("application/json", """{"serial":"SN-123","username":"alice","rotation_required":false,"new_secret_escrowed":true}""");

        using var client = new CryptServerClient(BaseUrl, mock);

        var result = await client.CheckinAsync(SampleCheckin());

        result.Serial.Should().Be("SN-123");
        result.Username.Should().Be("alice");
        result.RotationRequired.Should().BeFalse();
        result.NewSecretEscrowed.Should().BeTrue();
    }

    [Fact]
    public async Task CheckinAsync_401_ThrowsAuthExceptionWithoutRetry()
    {
        var mock = new MockHttpMessageHandler();
        var request = mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .Respond(HttpStatusCode.Unauthorized, "text/plain", "missing key");

        using var client = new CryptServerClient(BaseUrl, mock);

        var act = () => client.CheckinAsync(SampleCheckin(), retryCount: 3);

        var ex = await act.Should().ThrowAsync<CryptServerAuthException>();
        ex.Which.StatusCode.Should().Be(401);
        ex.Which.Message.Should().Contain("API key required");
        mock.GetMatchCount(request).Should().Be(1, "auth errors must not be retried");
    }

    [Fact]
    public async Task CheckinAsync_403_ThrowsAuthExceptionWithoutRetry()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .Respond(HttpStatusCode.Forbidden, "text/plain", "bad key");

        using var client = new CryptServerClient(BaseUrl, mock);

        var act = () => client.CheckinAsync(SampleCheckin(), retryCount: 3);

        var ex = await act.Should().ThrowAsync<CryptServerAuthException>();
        ex.Which.StatusCode.Should().Be(403);
        ex.Which.Message.Should().Contain("Invalid API key");
    }

    [Fact]
    public async Task CheckinAsync_PostsFormUrlEncodedBodyWithAllFields()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .WithFormData("serial", "SN-123")
            .WithFormData("recovery_password", "123456-789012-345678-901234-567890-123456-789012-345678")
            .WithFormData("username", "alice")
            .WithFormData("macname", "TEST-PC")
            .WithFormData("secret_type", "recovery_key")
            .Respond("application/json", """{"serial":"SN-123","username":"alice"}""");

        using var client = new CryptServerClient(BaseUrl, mock);

        await client.CheckinAsync(SampleCheckin());

        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task CheckinAsync_SendsApiKeyHeader()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .WithHeaders("X-API-Key", "secret123")
            .Respond("application/json", """{"serial":"SN-123"}""");

        var auth = new AuthConfig { ApiKey = "secret123" };
        using var client = new CryptServerClient(BaseUrl, mock, auth);

        await client.CheckinAsync(SampleCheckin());

        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task CheckinAsync_SendsCustomApiKeyHeader()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Post, $"{BaseUrl}/checkin/")
            .WithHeaders("Authorization", "Bearer deadbeef")
            .Respond("application/json", """{"serial":"SN-123"}""");

        var auth = new AuthConfig { ApiKey = "Bearer deadbeef", ApiKeyHeader = "Authorization" };
        using var client = new CryptServerClient(BaseUrl, mock, auth);

        await client.CheckinAsync(SampleCheckin());

        mock.VerifyNoOutstandingExpectation();
    }

    // -------------------------- VerifyAsync -------------------------

    [Fact]
    public async Task VerifyAsync_Success_ReturnsParsedResponse()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Get, $"{BaseUrl}/verify/SN-123/recovery_key/")
            .Respond("application/json", """{"escrowed":true,"date_escrowed":"2026-04-10T00:00:00Z"}""");

        using var client = new CryptServerClient(BaseUrl, mock);

        var result = await client.VerifyAsync("SN-123");

        result.Escrowed.Should().BeTrue();
        result.DateEscrowed.Should().Be("2026-04-10T00:00:00Z");
        result.Error.Should().BeNull();
    }

    [Fact]
    public async Task VerifyAsync_401_ThrowsAuthException()
    {
        var mock = new MockHttpMessageHandler();
        mock.When(HttpMethod.Get, $"{BaseUrl}/verify/SN-123/recovery_key/")
            .Respond(HttpStatusCode.Unauthorized, "text/plain", "missing key");

        using var client = new CryptServerClient(BaseUrl, mock);

        var act = () => client.VerifyAsync("SN-123");

        var ex = await act.Should().ThrowAsync<CryptServerAuthException>();
        ex.Which.StatusCode.Should().Be(401);
    }
}
