using System.Text.Json.Serialization;

// Define the configuration classes matching the JSON structure.
public class Config
{
    [JsonPropertyName("databases")]
    public List<DatabaseConfig> Databases { get; set; }
}

public class DatabaseConfig
{
    [JsonPropertyName("connectionString")]
    public string ConnectionString { get; set; }

    // Optional default query for the entire database.
    [JsonPropertyName("query")]
    public string Query { get; set; }

    [JsonPropertyName("tables")]
    public List<TableConfig> Tables { get; set; }
}

public class TableConfig
{
    [JsonPropertyName("tableName")]
    public string TableName { get; set; }

    [JsonPropertyName("outputFile")]
    public string OutputFile { get; set; }

    // Optional table-specific query which overrides the database default query.
    [JsonPropertyName("query")]
    public string Query { get; set; }
}