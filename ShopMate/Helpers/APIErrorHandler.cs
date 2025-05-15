using System.Net;
using System.Text.Json;

public static class ApiErrorHandler
{
    public static async Task<List<string>> HandleApiErrorAsync(HttpResponseMessage response)
    {
        var errors = new List<string>();

        if (response.IsSuccessStatusCode)
        {
            return errors;
        }

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            try
            {
                var errorDict = JsonSerializer.Deserialize<Dictionary<string, string[]>>(errorContent);
                if (errorDict != null)
                {
                    foreach (var error in errorDict)
                    {
                        foreach (var message in error.Value)
                        {
                            errors.Add(message);
                        }
                    }
                }
                else
                {
                    errors.Add("Invalid request.");
                }
            }
            catch (JsonException)
            {
                errors.Add(errorContent.Trim());
            }
        }
        else
        {
            //other status codes like 500
            errors.Add("Something went wrong. Please try again.");
        }
        return errors;
    }
}