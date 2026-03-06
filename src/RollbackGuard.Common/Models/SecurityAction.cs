namespace RollbackGuard.Common.Models;

public enum SecurityAction
{
    Allow = 0,
    Block = 2,
    Terminate = 7,
    Isolate = 8,
    Rollback = 9
}
