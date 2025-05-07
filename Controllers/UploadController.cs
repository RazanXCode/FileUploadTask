
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Text.RegularExpressions;

[ApiController]
[Route("[controller]")]
public class UploadController : ControllerBase
{
    private readonly Channel<FileUploadTask> _uploadChannel;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly ConcurrentDictionary<string, string> _statusMap;

    public UploadController(Channel<FileUploadTask> uploadChannel, IConfiguration config,
                            IWebHostEnvironment env, ConcurrentDictionary<string, string> statusMap)
    {
        _uploadChannel = uploadChannel;
        _config = config;
        _env = env;
        _statusMap = statusMap;
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file.Length > 10 * 1024 * 1024)
            return BadRequest("File too large.");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsRateLimitExceeded(ip))
            return BadRequest("Rate limit exceeded. Please try again later.");

        if (IsExecutableFile(file))
            return BadRequest("Executable files are not allowed.");

        var id = Guid.NewGuid().ToString();
        var sanitized = SanitizeFileName(file.FileName);

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var fileBytes = ms.ToArray();

        var simulateScan = bool.Parse(_config["SimulateAntivirusScan"] ?? "false");
        var delay = int.Parse(_config["ScanDelayMilliseconds"] ?? "2000");

        var storagePath = Path.Combine(_env.WebRootPath, "uploads");

        UploadStatusTracker.StatusMap[id] = "Pending";

        await _uploadChannel.Writer.WriteAsync(new FileUploadTask
        {
            ProcessingId = id,
            FileContent = fileBytes,
            OriginalFileName = sanitized,
            SimulateScan = simulateScan,
            ScanDelayMs = delay,
            StoragePath = storagePath
        });

        return Ok(new { processingId = id });
    }

    [HttpGet("status/{id}")]
    public IActionResult Status(string id)
    {
        if (!_statusMap.TryGetValue(id, out var status))
            return NotFound("Invalid ID");

        return Ok(new { status });
    }

    private static readonly Dictionary<string, List<DateTime>> UploadLog = new();

    private bool IsRateLimitExceeded(string ip, int maxUploads = 5, int intervalSeconds = 60)
    {
        lock (UploadLog)
        {
            if (!UploadLog.ContainsKey(ip))
                UploadLog[ip] = new List<DateTime>();

            var now = DateTime.UtcNow;
            UploadLog[ip].RemoveAll(t => (now - t).TotalSeconds > intervalSeconds);
            UploadLog[ip].Add(now);

            return UploadLog[ip].Count > maxUploads;
        }
    }

    private bool IsExecutableFile(IFormFile file)
    {
        using var reader = new BinaryReader(file.OpenReadStream());
        var headerBytes = reader.ReadBytes(4);
        return headerBytes.Length >= 2 && headerBytes[0] == 0x4D && headerBytes[1] == 0x5A; // MZ header
    }

    private string SanitizeFileName(string fileName)
    {
        return Regex.Replace(fileName, "[^a-zA-Z0-9_.-]", "_");
    }
}