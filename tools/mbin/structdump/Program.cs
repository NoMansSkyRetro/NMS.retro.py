// Dump every NMSTemplate struct's layout to JSON using libMBIN's own layout engine.
// Field offsets/sizes come from NMSTemplate.OffsetOf / SizeOf (the same code libMBIN uses
// to serialize), so this is the authoritative per-struct layout for whichever MBINCompiler
// build is referenced (the rc1 branch = the RC1/1.09-era retro definitions).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using libMBIN;

var baseType = typeof(NMSTemplate);
var asm = baseType.Assembly;
var result = new SortedDictionary<string, object>(StringComparer.Ordinal);

foreach (var t in asm.GetTypes())
{
    if (!t.IsSubclassOf(baseType) || t.IsAbstract) continue;

    ulong guid = 0;
    var attr = t.GetCustomAttribute<NMSAttribute>();
    if (attr != null) guid = attr.GUID;

    var fields = new List<Dictionary<string, object>>();
    foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.Instance))
    {
        int off, sz;
        try { off = NMSTemplate.OffsetOf(t, f.Name); } catch { off = -1; }
        try { sz = NMSTemplate.SizeOf(f); } catch { sz = -1; }
        fields.Add(new Dictionary<string, object> {
            ["name"] = f.Name,
            ["type"] = f.FieldType.Name,
            ["offset"] = off,
            ["size"] = sz,
        });
    }
    int total;
    try { total = NMSTemplate.SizeOf(t); } catch { total = -1; }

    result[t.Name] = new Dictionary<string, object> {
        ["guid"] = guid.ToString("X16"),
        ["size"] = total,
        ["fields"] = fields.OrderBy(x => (int)x["offset"]).ToList(),
    };
}

Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = false }));
Console.Error.WriteLine($"[structdump] {result.Count} templates");
