using CAFRS.Encryption.FIPS;
using Microsoft.Data.SqlClient; // For .NET Framework; for .NET Core, consider Microsoft.Data.SqlClient
using System.Text.Json;

namespace DecryptionApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Parse command line options.
            string path = null;
            bool processSubdirectories = false;
            string configFile = null;
            bool showHelp = false;
            CAFRSAESEncryptionEngine m_EncryptionEngine = new CAFRSAESEncryptionEngine();
            foreach (var arg in args)
            {
                if (arg.StartsWith("/p:", StringComparison.OrdinalIgnoreCase))
                {
                    path = arg.Substring(3);
                }
                else if (arg.Equals("/s", StringComparison.OrdinalIgnoreCase))
                {
                    processSubdirectories = true;
                }
                else if (arg.StartsWith("/config:", StringComparison.OrdinalIgnoreCase))
                {
                    configFile = arg.Substring(8);
                }
                else if (arg.Equals("/help", StringComparison.OrdinalIgnoreCase) || arg.Equals("/?", StringComparison.OrdinalIgnoreCase))
                {
                    showHelp = true;
                }
            }

            // If help requested, display help and exit.
            if (showHelp)
            {
                PrintHelp();
                return;
            }

            // If configuration mode is selected, stub it out.
            if (!string.IsNullOrEmpty(configFile))
            {
                Console.WriteLine("Database mode selected with config file: " + configFile);
                Console.WriteLine("Database decryption functionality is not yet implemented.");
                DecryptDatabases(m_EncryptionEngine, configFile);
                return;
            }

            // If a path is provided, process CSV file(s) from file or directory.
            if (!string.IsNullOrEmpty(path))
            {
                // Check if the path is a file.
                if (File.Exists(path))
                {
                    ProcessFile(path, m_EncryptionEngine);
                }
                // Else, if it's a directory.
                else if (Directory.Exists(path))
                {
                    var searchOption = processSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                    string[] csvFiles = Directory.GetFiles(path, "*.csv", searchOption);
                    if (csvFiles.Length == 0)
                    {
                        Console.WriteLine("No CSV files found in the specified directory.");
                    }
                    else
                    {
                        foreach (var file in csvFiles)
                        {
                            ProcessFile(file, m_EncryptionEngine);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("The provided path does not exist: " + path);
                }
            }
            else
            {
                Console.WriteLine("No valid command line options provided. Use /help or /? for usage information.");
            }
        }

        static private void DecryptDatabases(CAFRSAESEncryptionEngine m_EncryptionEngine, string jsonFilePath)
        {


            if (!File.Exists(jsonFilePath))
            {
                Console.WriteLine("Config file not found: " + jsonFilePath);
                return;
            }

            try
            {
                // Read and deserialize the JSON configuration.
                string jsonContent = File.ReadAllText(jsonFilePath);
                var config = JsonSerializer.Deserialize<Config>(jsonContent);

                if (config == null || config.Databases == null || config.Databases.Count == 0)
                {
                    Console.WriteLine("No database configurations found.");
                    return;
                }

                // Iterate through each database configuration.
                foreach (var db in config.Databases)
                {
                    Console.WriteLine("-------------------------------------------------");
                    Console.WriteLine("Processing database with connection string:");
                    Console.WriteLine(db.ConnectionString);

                    // Iterate through each table within the current database.
                    foreach (var table in db.Tables)
                    {
                        // Use the table-specific query if provided; otherwise, use the database-level query.
                        // If neither is provided, default to SELECT * from the table.
                        string query = !string.IsNullOrWhiteSpace(table.Query) ? table.Query :
                                       (!string.IsNullOrWhiteSpace(db.Query) ? db.Query : $"SELECT * FROM {table.TableName}");

                        Console.WriteLine("-------------------------------------------------");
                        Console.WriteLine("Table: " + table.TableName);
                        Console.WriteLine("Output File: " + table.OutputFile);
                        Console.WriteLine("Query: " + query);

                        ProcessDatabaseTable(db, table, m_EncryptionEngine);

                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while reading the config file: " + ex.Message);
            }
        }

        /// <summary>
        /// Processes a single table from the database using the provided configuration.
        /// </summary>
        /// <param name="dbConfig">The database configuration including the connection string and optional default query.</param>
        /// <param name="tableConfig">The table configuration containing the table name, output file name, and an optional query.</param>
        static void ProcessDatabaseTable(DatabaseConfig dbConfig, TableConfig tableConfig, CAFRSAESEncryptionEngine encEngine)
        {
            // Determine which query to use.
            string query;
            if (!string.IsNullOrWhiteSpace(tableConfig.Query))
            {
                query = tableConfig.Query;
            }
            else if (!string.IsNullOrWhiteSpace(dbConfig.Query))
            {
                query = dbConfig.Query;
            }
            else
            {
                query = $"SELECT * FROM {tableConfig.TableName}";
            }

            Console.WriteLine("Processing table: " + tableConfig.TableName);
            Console.WriteLine("Using query: " + query);

            List<string> errorLog = new List<string>();
            List<bool> decryptionEnabledColumns = new List<bool>();

            try
            {
                using (SqlConnection connection = new SqlConnection(dbConfig.ConnectionString))
                {
                    connection.Open();
                    using (SqlCommand command = new SqlCommand(query, connection))
                    using (SqlDataReader reader = command.ExecuteReader())
                    using (StreamWriter writer = new StreamWriter(tableConfig.OutputFile))
                    {
                        // Write header row.
                        int fieldCount = reader.FieldCount;
                        string[] headers = new string[fieldCount];
                        for (int i = 0; i < fieldCount; i++)
                        {
                            headers[i] = reader.GetName(i);
                        }
                        string headerRow = string.Join(",", headers);
                        writer.WriteLine(headerRow);
                        Console.WriteLine("Header: " + headerRow);

                        int rowNumber = 1; // Counter for data rows.
                        bool detectionRowProcessed = false;

                        while (reader.Read())
                        {
                            string[] inputColumns = new string[fieldCount];
                            string[] outputColumns = new string[fieldCount];

                            // Retrieve all column values as strings.
                            for (int i = 0; i < fieldCount; i++)
                            {
                                inputColumns[i] = reader.GetValue(i)?.ToString();
                            }

                            if (!detectionRowProcessed)
                            {
                                // First data row: try decrypting every column.
                                for (int i = 0; i < fieldCount; i++)
                                {
                                    try
                                    {
                                        outputColumns[i] = TryDecrypt(inputColumns[i], encEngine);
                                        decryptionEnabledColumns.Add(true);
                                    }
                                    catch (Exception)
                                    {
                                        outputColumns[i] = inputColumns[i];
                                        decryptionEnabledColumns.Add(false);
                                    }
                                }
                                detectionRowProcessed = true;
                            }
                            else
                            {
                                // For subsequent rows, only attempt decryption on columns flagged as encrypted.
                                for (int i = 0; i < fieldCount; i++)
                                {
                                    if (i < decryptionEnabledColumns.Count && decryptionEnabledColumns[i])
                                    {
                                        try
                                        {
                                            outputColumns[i] = TryDecrypt(inputColumns[i], encEngine);
                                        }
                                        catch (Exception ex)
                                        {
                                            errorLog.Add($"Row {rowNumber}, Column {i + 1}: {ex.Message}");
                                            outputColumns[i] = inputColumns[i];
                                        }
                                    }
                                    else
                                    {
                                        outputColumns[i] = inputColumns[i];
                                    }
                                }
                            }

                            // Log row details.
                            string inputRow = string.Join(",", inputColumns);
                            string outputRow = string.Join(",", outputColumns);
                            Console.WriteLine($"Row {rowNumber}: INPUT - {inputRow} OUTPUT - {outputRow}");

                            writer.WriteLine(outputRow);
                            rowNumber++;
                        }
                    }
                }

                if (errorLog.Count > 0)
                {
                    Console.WriteLine("Errors encountered while processing table: " + tableConfig.TableName);
                    foreach (var error in errorLog)
                    {
                        Console.WriteLine(error);
                    }
                }
                else
                {
                    Console.WriteLine("No decryption errors encountered for table: " + tableConfig.TableName);
                }
                Console.WriteLine("Output written to: " + tableConfig.OutputFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred processing table " + tableConfig.TableName + ": " + ex.Message);
            }
        }
        static void DecryptDatabase(DatabaseConfig dbConfig, CAFRSAESEncryptionEngine encryptionEngine)
        {

        }
        static void ProcessFile(string filePath, CAFRSAESEncryptionEngine decryptLibrary)
        {
            Console.WriteLine("\nProcessing file: " + filePath);
            string outputFilePath = GetOutputFileName(filePath);
            List<string> errorLog = new List<string>();
            List<bool> decryptionEnabledColumns = new List<bool>();
            int rowNumber = 0;
            bool headerWritten = false;
            bool detectionRowProcessed = false;

            try
            {
                using (var reader = new StreamReader(filePath))
                using (var writer = new StreamWriter(outputFilePath))
                {
                    string line;

                    while ((line = reader.ReadLine()) != null)
                    {
                        rowNumber++;

                        // Split CSV row into columns.
                        // NOTE: This simple split may not handle quoted commas properly.
                        var columns = line.Split(',');
                        string[] outputColumns = new string[columns.Length];

                        // First row is the header; write it as is.
                        if (!headerWritten)
                        {
                            writer.WriteLine(line);
                            Console.WriteLine($"Row {rowNumber} (Header): {line}");
                            headerWritten = true;
                            continue;
                        }

                        // The first data row: use it to determine which columns can be decrypted.
                        if (!detectionRowProcessed)
                        {
                            for (int i = 0; i < columns.Length; i++)
                            {
                                try
                                {
                                    outputColumns[i] = TryDecrypt(columns[i], decryptLibrary);
                                    decryptionEnabledColumns.Add(true);
                                }
                                catch (Exception)
                                {
                                    outputColumns[i] = columns[i];
                                    decryptionEnabledColumns.Add(false);
                                }
                            }
                            detectionRowProcessed = true;
                        }
                        else
                        {
                            // For subsequent rows, only attempt decryption for columns that were successful in the detection row.
                            for (int i = 0; i < columns.Length; i++)
                            {
                                if (i < decryptionEnabledColumns.Count && decryptionEnabledColumns[i])
                                {
                                    try
                                    {
                                        outputColumns[i] = TryDecrypt(columns[i], decryptLibrary);
                                    }
                                    catch (Exception ex)
                                    {
                                        string errorMessage = $"Row {rowNumber}, Column {i + 1}: {ex.Message}";
                                        errorLog.Add(errorMessage);
                                        outputColumns[i] = columns[i];
                                    }
                                }
                                else
                                {
                                    outputColumns[i] = columns[i];
                                }
                            }
                        }

                        // Create strings for input and output rows.
                        string inputRow = string.Join(",", columns);
                        string outputRow = string.Join(",", outputColumns);
                        Console.WriteLine($"Row {rowNumber}: INPUT - {inputRow} OUTPUT - {outputRow}");

                        // Write the output row to the file.
                        writer.WriteLine(outputRow);
                    }
                }

                if (errorLog.Count > 0)
                {
                    Console.WriteLine("\nErrors encountered in file " + filePath + ":");
                    foreach (var error in errorLog)
                    {
                        Console.WriteLine(error);
                    }
                }
                else
                {
                    Console.WriteLine("\nNo decryption errors encountered in file " + filePath + ".");
                }
                Console.WriteLine("Output written to: " + outputFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while processing the file " + filePath + ": " + ex.Message);
            }
        }


        /// <summary>
        /// Gets the output file name based on the input file name by appending "_DECRYPTED" before the extension.
        /// </summary>
        /// <param name="inputFilePath">The original file path.</param>
        /// <returns>The new output file path.</returns>
        static string GetOutputFileName(string inputFilePath)
        {
            string directory = Path.GetDirectoryName(inputFilePath);
            string filenameWithoutExt = Path.GetFileNameWithoutExtension(inputFilePath);
            string extension = Path.GetExtension(inputFilePath);
            return Path.Combine(directory, filenameWithoutExt + "_DECRYPTED" + extension);
        }

        /// <summary>
        /// A stub decryption method.
        /// In this example, if the input string starts with "ENC:" we assume it is encrypted and we "decrypt" it by removing the prefix.
        /// Otherwise, an exception is thrown.
        /// </summary>
        /// <param name="input">The input string to decrypt.</param>
        /// <returns>The decrypted string.</returns>
        static string TryDecrypt(string input, CAFRSAESEncryptionEngine decryptLibrary)
        {
            try
            {
                string decryptedData = decryptLibrary.DecryptString(input, decryptLibrary.PasswordStore.GetPassword("PII", PasswordStore.PasswordState.Decrypted));

                return decryptedData;

            }
            catch (Exception ex)
            {
                throw new Exception("Decryption failed: " + ex.Message);
            }
        }

        /// <summary>
        /// Prints the help message showing available command line options.
        /// </summary>
        static void PrintHelp()
        {
            Console.WriteLine("Usage: DecryptionApp [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  /p:<path>          Specify a file or directory containing CSV files to process.");
            Console.WriteLine("                     If a directory is specified, all CSV files will be processed.");
            Console.WriteLine("                     Use /s in addition to process subdirectories.");
            Console.WriteLine("  /config:<file.json> Specify a configuration JSON file for database mode (stubbed for now).");
            Console.WriteLine("  /help or /?        Display this help message.");
            Console.WriteLine();
            Console.WriteLine("Description:");
            Console.WriteLine("  This application reads CSV files and attempts to decrypt each column's data.");
            Console.WriteLine("  The first row is used to determine which columns contain encrypted data.");
            Console.WriteLine("  For subsequent rows, only the columns determined to be encrypted are decrypted.");
            Console.WriteLine("  Decrypted data is written to new CSV files with the suffix '_DECRYPTED'.");
        }
    }
}
