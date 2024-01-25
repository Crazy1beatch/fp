using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ResultOf;

namespace FileSenderRailway
{
    public class FileSender
    {
        private readonly ICryptographer cryptographer;
        private readonly IRecognizer recognizer;
        private readonly Func<DateTime> now;
        private readonly ISender sender;

        public FileSender(
            ICryptographer cryptographer,
            ISender sender,
            IRecognizer recognizer,
            Func<DateTime> now)
        {
            this.cryptographer = cryptographer;
            this.sender = sender;
            this.recognizer = recognizer;
            this.now = now;
        }

        public IEnumerable<FileSendResult> SendFiles(FileContent[] files, X509Certificate certificate)
        {
            return files
                .Select(file => new FileSendResult(
                    file,
                    PrepareFileToSend(file, certificate)
                        .RefineError("Can't prepare file to send")
                        .Then(sender.Send)
                        .RefineError("Can't send")
                        .Error
                ));
        }

        private Result<Document> PrepareFileToSend(FileContent fileContent, X509Certificate certificate)
        {
            return Result.Of(() => recognizer.Recognize(fileContent))
                .Then(CheckFormatVersion)
                .Then(CheckTimestamp)
                .Then(d => d with { Content = cryptographer.Sign(d.Content, certificate) });
        }

        private static Result<Document> CheckFormatVersion(Document doc)
        {
            return doc.Format is "4.0" or "3.1"
                ? new Result<Document>(null, doc)
                : new Result<Document>($"Invalid format version: {doc.Format}");
        }

        private Result<Document> CheckTimestamp(Document doc)
        {
            var oneMonthBefore = now().AddMonths(-1);
            return doc.Created > oneMonthBefore
                ? new Result<Document>(null, doc)
                : new Result<Document>($"Too old document, date of creation: {doc.Created}");
        }
    }
}
