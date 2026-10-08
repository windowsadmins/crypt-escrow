using System.Xml.Linq;
using CryptEscrow.Gui;
using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using CryptEscrow.Tests.Services;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Gui;

/// <summary>
/// The ADMX in resources/ must describe every setting the Prefs tab shows, with the value
/// name, type and choices the client reads.
/// </summary>
public class AdmxTemplateTests
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";

    private static readonly Lazy<XElement> Admx = new(() => XDocument.Load(RepoFile("resources", "Crypt.admx")).Root!);
    private static readonly Lazy<XElement> Adml = new(() => XDocument.Load(RepoFile("resources", "en-US", "Crypt.adml")).Root!);

    private static string RepoFile(params string[] parts)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "CryptEscrow.sln")))
                return Path.Combine([dir.FullName, .. parts]);
        }
        throw new FileNotFoundException("Repository root not found from " + AppContext.BaseDirectory);
    }

    private static IEnumerable<XElement> Policies => Admx.Value.Descendants(Ns + "policy");

    private static XElement PolicyFor(string valueName) =>
        Policies.Single(p => (string?)p.Attribute("valueName") == valueName
            || p.Descendants().Any(e => (string?)e.Attribute("valueName") == valueName));

    [Fact]
    public void EverySettingHasExactlyOnePolicy() =>
        Policies.Select(p => (string)p.Attribute("name")!)
            .Should().BeEquivalentTo(SettingsCatalog.Definitions.Select(d => d.Name));

    [Fact]
    public void EveryPolicyWritesTheKeyTheClientReads() =>
        Policies.Should().OnlyContain(p =>
            (string)p.Attribute("key")! == ConfigService.PolicyKeyPath && (string)p.Attribute("class")! == "Machine");

    public static IEnumerable<object[]> SettingNames =>
        SettingsCatalog.Definitions.Select(d => new object[] { d.Name });

    [Theory]
    [MemberData(nameof(SettingNames))]
    public void PolicyMatchesTheSettingsKindAndCard(string name)
    {
        var definition = SettingsCatalog.Definitions.Single(d => d.Name == name);
        var policy = PolicyFor(name);
        var elements = policy.Element(Ns + "elements")?.Elements().ToList() ?? [];

        ((string)policy.Element(Ns + "parentCategory")!.Attribute("ref")!).Should().Be(definition.Group);

        switch (definition.Kind)
        {
            case SettingKind.Toggle:
                elements.Should().BeEmpty();
                ((string)policy.Attribute("valueName")!).Should().Be(name);
                ((string)policy.Element(Ns + "enabledValue")!.Element(Ns + "decimal")!.Attribute("value")!).Should().Be("1");
                ((string)policy.Element(Ns + "disabledValue")!.Element(Ns + "decimal")!.Attribute("value")!).Should().Be("0");
                break;
            case SettingKind.Number:
                elements.Should().ContainSingle().Which.Name.Should().Be(Ns + "decimal");
                break;
            case SettingKind.Choice:
                var element = elements.Should().ContainSingle().Which;
                element.Name.Should().Be(Ns + "enum");
                element.Descendants(Ns + "string").Select(s => s.Value)
                    .Should().Equal(definition.Choices);
                break;
            default:
                elements.Should().ContainSingle().Which.Name.Should().Be(Ns + "text");
                break;
        }

        // An enabled policy with an empty value would read as unset and leave the field unlocked.
        elements.All(e => (string?)e.Attribute("required") == "true").Should().BeTrue();
        elements.All(e => (string?)e.Attribute("valueName") == name).Should().BeTrue();
    }

    [Fact]
    public void CategoriesMirrorThePrefsCards() =>
        Admx.Value.Descendants(Ns + "category")
            .Where(c => (string?)c.Element(Ns + "parentCategory")?.Attribute("ref") == "ManagedEncryption")
            .Select(c => (string)c.Attribute("name")!)
            .Should().Equal(SettingsCatalog.Groups);

    [Fact]
    public void EveryStringAndPresentationTheAdmxNamesIsInTheAdml()
    {
        var admx = File.ReadAllText(RepoFile("resources", "Crypt.admx"));
        var strings = Adml.Value.Descendants(Ns + "string").Select(s => (string)s.Attribute("id")!).ToHashSet();
        var presentations = Adml.Value.Descendants(Ns + "presentation").Select(s => (string)s.Attribute("id")!).ToHashSet();

        System.Text.RegularExpressions.Regex.Matches(admx, @"\$\(string\.([^)]+)\)").Select(m => m.Groups[1].Value)
            .Should().OnlyContain(id => strings.Contains(id));
        System.Text.RegularExpressions.Regex.Matches(admx, @"\$\(presentation\.([^)]+)\)").Select(m => m.Groups[1].Value)
            .Should().OnlyContain(id => presentations.Contains(id));
    }

    [Fact]
    public void ApiKeyExplainsWhereThePolicyValueEndsUp()
    {
        var help = Adml.Value.Descendants(Ns + "string").Single(s => (string?)s.Attribute("id") == "ApiKey_Help").Value;

        help.Should().Contain("first elevated run").And.Contain(@"HKLM\SOFTWARE\Crypt\ManagedEncryption\Secrets")
            .And.Contain("readable");
    }
}

/// <summary>A value of the shape the ADMX writes locks its field in the Prefs tab.</summary>
[Collection(GlobalStateCollection.Name)]
public class PolicyLocksEveryFieldTests
{
    public static IEnumerable<object[]> SettingNames =>
        SettingsCatalog.Definitions.Select(d => new object[] { d.Name });

    [Theory]
    [MemberData(nameof(SettingNames))]
    public void PolicyValueLocksTheField(string name)
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        var definition = SettingsCatalog.Definitions.Single(d => d.Name == name);

        string? expected;
        switch (definition.Kind)
        {
            case SettingKind.Toggle:
                reg.SetDword(name, 0);
                expected = "0";
                break;
            case SettingKind.Number:
                reg.SetDword(name, 7);
                expected = "7";
                break;
            case SettingKind.Choice:
                expected = definition.Choices![^1];
                reg.SetString(name, expected);
                break;
            case SettingKind.Secret:
                reg.SetString(name, "from-policy");
                expected = null;
                break;
            default:
                expected = "from-policy";
                reg.SetString(name, expected);
                break;
        }

        var state = SettingsCatalog.Load().Single(s => s.Definition.Name == name);

        state.IsManaged.Should().BeTrue();
        state.FieldValue.Should().Be(expected);
        if (definition.Kind == SettingKind.Toggle)
            state.ToggleValue.Should().BeFalse();
        PrefsElevation.CanEdit(isElevated: true, state.IsManaged).Should().BeFalse();
        var save = () => SettingsCatalog.Save(name, "changed");
        save.Should().Throw<InvalidOperationException>();
    }
}
