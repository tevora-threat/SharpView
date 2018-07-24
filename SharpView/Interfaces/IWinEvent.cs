using System;

namespace SharpView.Interfaces
{
    public interface IWinEvent
    {
        string ComputerName { get; set; }

        DateTime? TimeCreated { get; set; }

        int EventId { get; set; }
    }
}
