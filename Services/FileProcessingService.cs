using System.Threading.Channels;
using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;

public class FileProcessingService : BackgroundService
{
    private readonly Channel<FileUploadTask> _uploadChannel;
    private readonly ILogger<FileProcessingService> _logger;

    public FileProcessingService(Channel<FileUploadTask> uploadChannel, ILogger<FileProcessingService> logger)
    {
        _uploadChannel = uploadChannel;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var task in _uploadChannel.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                _logger.LogInformation("Processing file: {FileName}", task.OriginalFileName);
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Scanning";

                if (task.SimulateScan)
                    await Task.Delay(task.ScanDelayMs, stoppingToken);

                if (!IsFileHeaderValid(task.FileContent))
                {
                    UploadStatusTracker.StatusMap[task.ProcessingId] = "VirusDetected";
                    continue;
                }

                UploadStatusTracker.StatusMap[task.ProcessingId] = "Processing";

                Directory.CreateDirectory(task.StoragePath);
                var filePath = Path.Combine(task.StoragePath, task.OriginalFileName);
                await File.WriteAllBytesAsync(filePath, task.FileContent, stoppingToken);

                UploadStatusTracker.StatusMap[task.ProcessingId] = "Completed";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process file {FileName}", task.OriginalFileName);
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Failed";
            }
        }
    }

    private bool IsFileHeaderValid(byte[] content)
    {
        if (content.Length < 4) return false;

        if (content[0] == 0x25 && content[1] == 0x50 && content[2] == 0x44 && content[3] == 0x46) return true; // PDF
        if (content[0] == 0xFF && content[1] == 0xD8) return true; // JPEG
        if (content[0] == 0x50 && content[1] == 0x4B) return true; // DOCX/ZIP
        if (content.Take(4).All(b => b < 128)) return true; // Likely ASCII/UTF-8

        return false;
    }
}