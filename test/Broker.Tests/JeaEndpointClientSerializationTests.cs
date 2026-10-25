using System.Collections;
using System.Management.Automation;
using Broker.JeaExecution;
using Xunit;

namespace Broker.Tests;

/// <summary>
/// Covers JeaEndpointClient.ToSerializable — the fix for "JEA output comes back empty"
/// (original critique item 5). A raw PSObject/PSCustomObject serializes to "{}" via
/// System.Text.Json, so this flattens PowerShell output into plain CLR values first.
/// This had zero coverage despite being one of the original critique's confirmed bugs;
/// these tests use real System.Management.Automation types, not fakes.
/// </summary>
public class JeaEndpointClientSerializationTests
{
    /// <summary>
    /// Builds a real PSCustomObject — matching what [pscustomobject]@{} produces in
    /// PowerShell. A bare `new PSObject()` already has BaseObject of type PSCustomObject,
    /// so `.Properties.Add` works directly — the earlier failure came from going through
    /// the extra `.PSObject` indirection (`obj.PSObject.Properties`), which double-wraps
    /// into a PSObject-of-a-PSObject whose BaseObject is no longer PSCustomObject.
    /// </summary>
    private static PSObject MakePSCustomObject(params (string Name, object? Value)[] props)
    {
        var obj = new PSObject();
        foreach (var (name, value) in props)
            obj.Properties.Add(new PSNoteProperty(name, value));
        return obj;
    }

    [Fact]
    public void NullPassesThrough()
    {
        Assert.Null(JeaEndpointClient.ToSerializable(null));
    }

    [Fact]
    public void PlainStringStaysAString()
    {
        // string implements IEnumerable<char> — must not be exploded into a char array.
        var result = JeaEndpointClient.ToSerializable("hello");
        Assert.Equal("hello", result);
    }

    [Fact]
    public void PlainPrimitivePassesThrough()
    {
        Assert.Equal(42, JeaEndpointClient.ToSerializable(42));
        Assert.Equal(true, JeaEndpointClient.ToSerializable(true));
    }

    [Fact]
    public void PSCustomObjectFlattensToDictionary()
    {
        var obj = MakePSCustomObject(("Name", "ListJeaEndpoints"), ("Enabled", true));

        var result = JeaEndpointClient.ToSerializable(obj);

        var dict = Assert.IsType<Dictionary<string, object?>>(result);
        Assert.Equal("ListJeaEndpoints", dict["Name"]);
        Assert.Equal(true, dict["Enabled"]);
    }

    [Fact]
    public void WrappedPrimitiveUnwrapsToBaseObject()
    {
        // PSObject.AsPSObject is how PowerShell's own pipeline wraps a primitive output —
        // BaseObject is the int itself, not a PSCustomObject, so it must unwrap, not flatten.
        var wrapped = PSObject.AsPSObject(99);
        var result = JeaEndpointClient.ToSerializable(wrapped);
        Assert.Equal(99, result);
    }

    [Fact]
    public void NestedPSObjectPropertyFlattensRecursively()
    {
        var inner = MakePSCustomObject(("SamAccountName", "jdoe"));
        var outer = MakePSCustomObject(("User", inner));

        var result = JeaEndpointClient.ToSerializable(outer);

        var outerDict = Assert.IsType<Dictionary<string, object?>>(result);
        var innerDict = Assert.IsType<Dictionary<string, object?>>(outerDict["User"]);
        Assert.Equal("jdoe", innerDict["SamAccountName"]);
    }

    [Fact]
    public void ArrayOfPSObjectsFlattensElementwise()
    {
        var item1 = MakePSCustomObject(("Id", 1));
        var item2 = MakePSCustomObject(("Id", 2));

        object?[] array = [item1, item2];
        var result = JeaEndpointClient.ToSerializable(array);

        var items = Assert.IsType<object?[]>(result);
        Assert.Equal(2, items.Length);
        Assert.Equal(1, Assert.IsType<Dictionary<string, object?>>(items[0])["Id"]);
        Assert.Equal(2, Assert.IsType<Dictionary<string, object?>>(items[1])["Id"]);
    }

    [Fact]
    public void HashtableFlattensToStringKeyedDictionary()
    {
        var table = new Hashtable { ["Name"] = "Get-Thing", ["Count"] = 3 };
        var result = JeaEndpointClient.ToSerializable(table);

        var dict = Assert.IsType<Dictionary<string, object?>>(result);
        Assert.Equal("Get-Thing", dict["Name"]);
        Assert.Equal(3, dict["Count"]);
    }
}
