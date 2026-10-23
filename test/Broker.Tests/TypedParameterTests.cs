using System.Globalization;
using Broker.Core;
using Broker.Policy;
using Broker.Registry;
using Xunit;

namespace Broker.Tests;

public class TypedParameterTests
{
    private readonly ParameterValidator _validator = new();
    private readonly ArgvBuilder _argv = new();

    private static ToolManifest Tool(string type, ParameterAllowlist allow, bool required = false) => new()
    {
        ToolId = "typed-tool",
        RiskTierRaw = "read",
        Parameters = { new ToolParameter { Name = "P", Type = type, Required = required, Allowlist = allow } }
    };

    private static ParameterAllowlist DaysRange => new() { Range = new ParamRange { Min = 1, Max = 30 } };
    private static ParameterAllowlist AnyInt => new() { MaxLength = 12 };
    private static ParameterAllowlist BoolEnum => new() { EnumValues = new() { "true", "false" } };

    private PolicyDecision Validate(ToolManifest t, string value) =>
        _validator.Validate(t, new Dictionary<string, string> { ["P"] = value });

    [Theory]
    [InlineData("1", true)]
    [InlineData("30", true)]
    [InlineData("15", true)]
    [InlineData("0", false)]          // below minimum
    [InlineData("31", false)]         // above maximum
    [InlineData("-1", false)]         // negative where prohibited by the range
    [InlineData("1.5", false)]        // decimal supplied to an integer parameter
    [InlineData("1e1", false)]        // exponent form: a double parser accepts it, an int parser does not
    [InlineData("NaN", false)]        // NaN compares false against every bound
    [InlineData("Infinity", false)]
    [InlineData("-Infinity", false)]
    [InlineData("99999999999", false)]// int overflow
    [InlineData("", false)]
    [InlineData(" 5", false)]
    [InlineData("5 ", false)]
    [InlineData("+5", false)]
    [InlineData("0x10", false)]
    [InlineData("1,5", false)]
    [InlineData("١٥", false)]         // Arabic-Indic digits: char.IsDigit is true, must still be rejected
    public void IntegerRangeParameterIsValidatedWithTheSameRulesTheConverterUses(string value, bool allowed)
    {
        var d = Validate(Tool("int", DaysRange), value);
        Assert.Equal(allowed, d.Allowed);
        if (!allowed) Assert.False(string.IsNullOrEmpty(d.Reason));
    }

    [Theory]
    [InlineData("2147483647", true)]
    [InlineData("-2147483648", true)]
    [InlineData("2147483648", false)]
    [InlineData("-2147483649", false)]
    [InlineData("007", true)]
    [InlineData("--1", false)]
    [InlineData("1-", false)]
    public void IntegerBoundariesAreInt32(string value, bool allowed)
    {
        var d = Validate(Tool("int", AnyInt), value);
        Assert.Equal(allowed, d.Allowed);
        if (!allowed) Assert.Equal("parameter-not-integer:P", d.Reason);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", true)]
    [InlineData("True", false)]
    [InlineData("TRUE", false)]
    [InlineData(" true", false)]
    [InlineData("yes", false)]
    [InlineData("1", false)]
    [InlineData("", false)]
    public void BooleanParameterAcceptsOnlyLowerCaseTrueOrFalse(string value, bool allowed)
    {
        Assert.Equal(allowed, Validate(Tool("bool", BoolEnum), value).Allowed);
    }

    [Theory]
    [InlineData("True")]
    [InlineData("yes")]
    [InlineData(" true ")]
    [InlineData("")]
    public void BooleanTypeIsCheckedEvenWhenTheManifestConstraintIsOnlyALength(string value)
    {
        // A manifest that constrains a bool by length alone must not let bool.Parse-style leniency
        // (case-insensitive, whitespace-trimming) differ from what the validator checked.
        var d = Validate(Tool("bool", new ParameterAllowlist { MaxLength = 8 }), value);
        Assert.False(d.Allowed);
        Assert.Equal("parameter-not-boolean:P", d.Reason);
    }

    [Fact]
    public void ValidationAndConversionAgreeForEveryIntegerTheValidatorAccepts()
    {
        var tool = Tool("int", AnyInt);
        foreach (var v in new[] { "0", "7", "-7", "007", "2147483647", "-2147483648" })
        {
            Assert.True(Validate(tool, v).Allowed, v);
            var argv = _argv.Build(tool, new Dictionary<string, string> { ["P"] = v });
            Assert.Equal(int.Parse(v, CultureInfo.InvariantCulture), Assert.IsType<int>(argv["P"]));
        }
    }

    [Theory]
    [InlineData("int", "1.5")]
    [InlineData("int", "abc")]
    [InlineData("int", "99999999999")]
    [InlineData("int", "")]
    [InlineData("bool", "yes")]
    [InlineData("bool", "True")]
    [InlineData("bool", "")]
    public void ArgvBuilderRefusesUnvalidatedBadValuesWithoutLeakingFormatException(string type, string value)
    {
        var tool = Tool(type, new ParameterAllowlist { MaxLength = 20 });
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _argv.Build(tool, new Dictionary<string, string> { ["P"] = value }));

        // The raw value must not be echoed into diagnostics that may reach a client.
        if (value.Length > 0) Assert.DoesNotContain(value, ex.Message);
    }

    [Fact]
    public void ArgvBuilderRefusesParametersThatAreNotInTheManifest()
    {
        var tool = Tool("string", new ParameterAllowlist { MaxLength = 5 });
        Assert.Throws<InvalidOperationException>(() =>
            _argv.Build(tool, new Dictionary<string, string> { ["P"] = "ok", ["Injected"] = "x" }));
    }

    [Theory]
    [InlineData("datetime")]
    [InlineData("")]
    [InlineData("INT")]
    public void UnsupportedParameterTypeIsRejectedByBothValidatorAndBuilder(string type)
    {
        var tool = Tool(type, new ParameterAllowlist { MaxLength = 5 });

        var d = Validate(tool, "1");
        Assert.False(d.Allowed);
        Assert.Equal("parameter-type-unsupported:P", d.Reason);
        Assert.Throws<InvalidOperationException>(() => _argv.Build(tool, new Dictionary<string, string> { ["P"] = "1" }));
    }

    [Fact]
    public void EnumTypedParameterIsPassedThroughAsString()
    {
        var tool = Tool("enum", new ParameterAllowlist { EnumValues = new() { "Start", "Stop" } });
        Assert.True(Validate(tool, "Start").Allowed);
        Assert.Equal("Start", _argv.Build(tool, new Dictionary<string, string> { ["P"] = "Start" })["P"]);
    }

    [Fact]
    public void MissingOptionalValueIsOmittedNotDefaulted()
    {
        var tool = Tool("int", DaysRange, required: false);
        Assert.True(_validator.Validate(tool, new Dictionary<string, string>()).Allowed);
        var argv = _argv.Build(tool, new Dictionary<string, string>());
        Assert.False(argv.ContainsKey("P"));
    }

    [Fact]
    public void MissingRequiredValueIsRejected()
    {
        var d = _validator.Validate(Tool("int", DaysRange, required: true), new Dictionary<string, string>());
        Assert.False(d.Allowed);
        Assert.Equal("missing-required-parameter:P", d.Reason);
    }

    [Theory]
    [InlineData("1,5")]
    [InlineData("1.000")]
    [InlineData("1,000")]
    public void ParsingDoesNotDependOnTheCurrentCulture(string value)
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            var odd = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            odd.NumberFormat.NumberDecimalSeparator = ",";
            odd.NumberFormat.NumberGroupSeparator = ".";
            CultureInfo.CurrentCulture = odd;

            Assert.False(Validate(Tool("int", DaysRange), value).Allowed);
            Assert.False(Validate(Tool("int", AnyInt), value).Allowed);
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Fact]
    public void NonIntegerRangeParameterRejectsNonFiniteNumbers()
    {
        var tool = Tool("string", new ParameterAllowlist { Range = new ParamRange { Min = 0, Max = 10 } });
        Assert.True(Validate(tool, "2.5").Allowed);
        Assert.False(Validate(tool, "NaN").Allowed);
        Assert.False(Validate(tool, "Infinity").Allowed);
        Assert.False(Validate(tool, "11").Allowed);
    }

    [Theory]
    [InlineData("a\nb")]
    [InlineData("ab\n")]
    [InlineData("ab\r")]
    [InlineData("a\tb")]
    [InlineData("a\0b")]
    public void ControlCharactersAreRejectedEvenWhenTheRegexWouldAcceptThem(string value)
    {
        // `$` matches before a trailing "\n", so ^[a-z]+$ accepts "ab\n" on its own.
        var tool = Tool("string", new ParameterAllowlist { RegexPattern = "^[a-z\\s]+$" });
        var d = Validate(tool, value);
        Assert.False(d.Allowed);
        Assert.Equal("parameter-control-character:P", d.Reason);
    }
}

public class ManifestTierHardeningTests
{
    private static ToolManifest Tool(string tier, bool? requiresElicitation = null) => new()
    {
        ToolId = "t",
        RiskTierRaw = tier,
        RequiresElicitation = requiresElicitation
    };

    [Theory]
    [InlineData("write")]
    [InlineData("destructive")]
    public void WriteAndDestructiveToolsAlwaysRequireElicitationEvenIfTheManifestSaysOtherwise(string tier)
    {
        Assert.True(Tool(tier, requiresElicitation: null).ElicitationRequired);
        Assert.True(Tool(tier, requiresElicitation: true).ElicitationRequired);
        Assert.True(Tool(tier, requiresElicitation: false).ElicitationRequired,
            "requiresElicitation:false must not be able to switch approval off for a mutating tool");
    }

    [Fact]
    public void ReadToolsCanOptInToElicitationButNotByDefault()
    {
        Assert.False(Tool("read").ElicitationRequired);
        Assert.False(Tool("read", false).ElicitationRequired);
        Assert.True(Tool("read", true).ElicitationRequired);
    }

    [Theory]
    [InlineData("Write")]
    [InlineData("WRITE")]
    [InlineData("write")]
    public void RiskTierIsCaseInsensitive(string raw) => Assert.Equal(RiskTier.Write, Tool(raw).RiskTier);

    [Theory]
    [InlineData("")]
    [InlineData("wrte")]
    [InlineData(" write")]
    [InlineData("write ")]
    [InlineData("admin")]
    [InlineData("none")]
    public void UnrecognizedRiskTierFailsClosedToTheMostRestrictiveTier(string raw)
    {
        var t = Tool(raw);
        Assert.False(t.HasRecognizedRiskTier);
        Assert.Equal(RiskTier.Destructive, t.RiskTier);
        Assert.True(t.ElicitationRequired);
    }
}
