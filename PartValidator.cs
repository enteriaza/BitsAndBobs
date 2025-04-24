using System.Text;
using System.Text.RegularExpressions;

namespace yEnc
{
    /// <summary>
    /// Validates a yEnc part by verifying its CRC32 checksum, and ensuring its structure adheres to the yEnc format.
    /// </summary>
    public class PartValidator
    {
        /// <summary>
        /// Represents the result of a yEnc validation process.
        /// </summary>
        public class ValidationResult
        {
            public bool Success { get; set; } // Indicates if validation was successful.
            public string? ExpectedCrc32 { get; set; } // Expected CRC32 checksum from the yEnc footer.
            public uint ActualCrc32 { get; set; } // Computed CRC32 checksum of the decoded data.
            public byte[]? DecodedBytes { get; set; } // Decoded payload bytes.
            public string? Error { get; set; } // Error message if validation fails.
        }

        private static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");

        /// <summary>
        /// Validates a yEnc part from a byte array.
        /// </summary>
        /// <param name="yEncData">The yEnc-encoded data as a byte array.</param>
        /// <param name="strict">If true, performs strict validation of line lengths and escape sequences.</param>
        /// <returns>A ValidationResult object containing the validation outcome.</returns>
        public static ValidationResult Validate(byte[] yEncData, bool strict = false)
        {
            string yEncText = Latin1.GetString(yEncData);
            return Validate(yEncText, strict);
        }

        /// <summary>
        /// Validates a yEnc part from a string.
        /// </summary>
        /// <param name="yEncText">The yEnc-encoded data as a string.</param>
        /// <param name="strict">If true, performs strict validation of line lengths and escape sequences.</param>
        /// <returns>A ValidationResult object containing the validation outcome.</returns>
        public static ValidationResult Validate(string yEncText, bool strict = false)
        {
            try
            {
                var lines = yEncText.Split(["\r\n", "\n"], StringSplitOptions.None);

                if (strict)
                {
                    // Perform strict validation of line lengths and escape sequences.
                    for (int i = 0; i < lines.Length; i++)
                    {
                        string line = lines[i];

                        if (line.Length > 998)
                        {
                            return new ValidationResult
                            {
                                Success = false,
                                Error = $"Line {i + 1} exceeds 998 characters (length: {line.Length})"
                            };
                        }

                        for (int j = 0; j < line.Length; j++)
                        {
                            char c = line[j];

                            if (c == '=')
                            {
                                if (j + 1 >= line.Length || !IsValidEscape(line[j + 1]))
                                {
                                    return new ValidationResult
                                    {
                                        Success = false,
                                        Error = $"Invalid escape sequence at line {i + 1}, col {j + 1}"
                                    };
                                }
                                j++; // Skip escaped character.
                            }
                            else if (c < 32 && c != '\t')
                            {
                                return new ValidationResult
                                {
                                    Success = false,
                                    Error = $"Unescaped control character (0x{(int)c:X2}) at line {i + 1}, col {j + 1}"
                                };
                            }
                        }
                    }
                }

                return ValidateInternal(yEncText, lines);
            }
            catch (Exception ex)
            {
                return new ValidationResult { Success = false, Error = ex.Message };
            }
        }

        /// <summary>
        /// Internal validation logic for yEnc data.
        /// </summary>
        private static ValidationResult ValidateInternal(string yEncText, string[] lines)
        {
            int beginIndex = Array.FindIndex(lines, l => l.StartsWith("=ybegin"));
            int endIndex = Array.FindLastIndex(lines, l => l.StartsWith("=yend"));

            if (beginIndex == -1 || endIndex == -1 || endIndex <= beginIndex)
                return new ValidationResult { Success = false, Error = "Missing =ybegin or =yend" };

            var footer = ParseKeyValueLine(lines[endIndex]);

            if (!footer.TryGetValue("crc32", out string? expectedCrc) || expectedCrc is null)
                return new ValidationResult { Success = false, Error = "No valid crc32 in footer" };

            int partLineIndex = Array.FindIndex(lines, beginIndex + 1, endIndex - beginIndex - 1, l => l.StartsWith("=ypart"));
            int payloadStart = partLineIndex != -1 ? partLineIndex + 1 : beginIndex + 1;

            var payloadLines = lines[payloadStart..endIndex];
            var encodedPayload = string.Join("\n", payloadLines);

            byte[] decodedBytes = DecodeYEnc(encodedPayload);
            uint actualCrc = ComputeCrc32(decodedBytes);

            // Validate size if specified in the footer.
            if (footer.TryGetValue("size", out string? sizeStr) && int.TryParse(sizeStr, out int expectedSize))
            {
                if (decodedBytes.Length != expectedSize)
                {
                    return new ValidationResult
                    {
                        Success = false,
                        Error = $"Size mismatch: expected {expectedSize}, got {decodedBytes.Length}"
                    };
                }
            }

            // Validate offsets if =ypart is present.
            if (partLineIndex != -1)
            {
                var offsets = ParseKeyValueLine(lines[partLineIndex]);
                if (offsets.TryGetValue("begin", out string? bStr) &&
                    offsets.TryGetValue("end", out string? eStr) &&
                    int.TryParse(bStr, out int begin) &&
                    int.TryParse(eStr, out int end))
                {
                    int expectedLength = end - begin + 1;
                    if (decodedBytes.Length != expectedLength)
                    {
                        return new ValidationResult
                        {
                            Success = false,
                            Error = $"Offset mismatch: expected {expectedLength} bytes, got {decodedBytes.Length}"
                        };
                    }
                }
            }

            return new ValidationResult
            {
                Success = actualCrc == Convert.ToUInt32(expectedCrc, 16),
                ExpectedCrc32 = expectedCrc,
                ActualCrc32 = actualCrc,
                DecodedBytes = decodedBytes
            };
        }

        /// <summary>
        /// Parses a key-value pair line from the yEnc metadata.
        /// </summary>
        private static Dictionary<string, string> ParseKeyValueLine(string line)
        {
            var result = new Dictionary<string, string>();
            var matches = Regex.Matches(line, @"(\w+)=([^\s]+)");
            foreach (Match match in matches)
                result[match.Groups[1].Value] = match.Groups[2].Value;
            return result;
        }

        /// <summary>
        /// Checks if a character is a valid escape sequence in yEnc.
        /// </summary>
        private static bool IsValidEscape(char next) => next >= ' ' && next <= '~';

        /// <summary>
        /// Decodes a yEnc-encoded string into its original byte array.
        /// </summary>
        public static byte[] DecodeYEnc(string encoded)
        {
            List<byte> output = [];
            bool escape = false;

            foreach (char c in encoded)
            {
                if (escape)
                {
                    output.Add((byte)(((byte)c - 64 - 42 + 256) % 256));
                    escape = false;
                }
                else if (c == '=')
                {
                    escape = true;
                }
                else
                {
                    output.Add((byte)(((byte)c - 42 + 256) % 256));
                }
            }

            return [.. output];
        }

        /// <summary>
        /// Computes the CRC32 checksum for a byte array.
        /// </summary>
        public static uint ComputeCrc32(byte[] bytes)
        {
            const uint poly = 0xEDB88320;
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int j = 0; j < 8; j++)
                    c = (c & 1) != 0 ? poly ^ c >> 1 : c >> 1;
                table[i] = c;
            }

            uint crc = 0xFFFFFFFF;
            foreach (byte b in bytes)
                crc = table[(crc ^ b) & 0xFF] ^ crc >> 8;

            return crc ^ 0xFFFFFFFF;
        }
    }
}
