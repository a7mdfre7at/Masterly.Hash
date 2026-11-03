using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>
/// Regression for the Windows CI thread-pool starvation: Argon2 must run every lane on the calling thread. A
/// derivation that queues lanes as tasks and blocks on them (sync-over-async) deadlocks the hasher's
/// concurrency gate when the pool is small, because gate waiters hold the pool threads the lane tasks need.
/// </summary>
/// <remarks>
/// Deterministic: TplEventSource is a managed EventSource, so its events are dispatched synchronously on the
/// thread that raised them. A listener that only counts events raised on the test's own thread, between two
/// points the test controls, sees exactly what the derivation scheduled or waited on. No timing is involved.
/// </remarks>
public class Argon2SchedulingTests
{
    public static IEnumerable<object[]> Profiles()
    {
        yield return new object[] { 64, 1, 1 };
        yield return new object[] { 256, 2, 4 };
        yield return new object[] { 1024, 1, 8 };
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void DeriveKey_SchedulesNoTasksAndBlocksOnNoTasks_FromTheCallingThread(int memoryKiB, int iterations, int parallelism)
    {
        HashProfile profile = HashProfile.Argon2id("sched-test", memoryKiB, iterations, parallelism);
        byte[] input = Encoding.UTF8.GetBytes("pw");
        byte[] salt = new byte[16];

        using TaskEventRecorder recorder = new TaskEventRecorder();
        recorder.Start();
        byte[] tag = HashPrimitives.DeriveKey(profile, input, salt);
        IReadOnlyList<string> events = recorder.Stop();

        Assert.Equal(32, tag.Length);
        Assert.True(events.Count == 0, $"Argon2 scheduled or waited on tasks from the calling thread: {string.Join(", ", events)}");
    }

    [Fact]
    public void PasswordHasher_HashAndVerify_ScheduleNoTasks_FromTheCallingThread()
    {
        PasswordHasher hasher = TestHashers.Create();

        using TaskEventRecorder recorder = new TaskEventRecorder();
        recorder.Start();
        string hash = hasher.Hash("pw");
        bool match = hasher.Verify("pw", hash).IsMatch;
        IReadOnlyList<string> events = recorder.Stop();

        Assert.True(match);
        Assert.True(events.Count == 0, $"The hasher scheduled or waited on tasks from the calling thread: {string.Join(", ", events)}");
    }

    [Fact]
    public async Task Recorder_SeesTasksScheduled_FromTheCallingThread()
    {
        // Guards the test itself: if the event source stopped reporting, the assertions above would pass vacuously.
        // TaskScheduled is raised by Task.Run on the calling thread, so the task is awaited only after recording stops.
        using TaskEventRecorder recorder = new TaskEventRecorder();
        recorder.Start();
        Task<int> scheduled = Task.Run(() => 42);
        IReadOnlyList<string> events = recorder.Stop();

        Assert.Equal(42, await scheduled);
        Assert.Contains("TaskScheduled", events);
    }

    /// <summary>Records TPL scheduling and blocking-wait events raised on one thread while armed.</summary>
    private sealed class TaskEventRecorder : EventListener
    {
        private const string TplEventSourceName = "System.Threading.Tasks.TplEventSource";

        // TplEventSource.Keywords.TaskTransfer | Keywords.Tasks: TaskScheduled, TaskStarted, TaskWaitBegin, ...
        // Deliberately not TasksFlowActivityIds / TasksSetActivityIds, which change activity tracking process-wide.
        private const EventKeywords TaskKeywords = (EventKeywords)0x3;

        private static readonly HashSet<string> Recorded = new HashSet<string>(StringComparer.Ordinal)
        {
            "TaskScheduled",
            "TaskWaitBegin",
            "AwaitTaskContinuationScheduled",
        };

        private readonly List<string> _events = new List<string>();
        private readonly object _lock = new object();
        private int _threadId = -1;

        public void Start()
        {
            lock (_lock)
                _events.Clear();
            Volatile.Write(ref _threadId, Environment.CurrentManagedThreadId);
        }

        public IReadOnlyList<string> Stop()
        {
            Volatile.Write(ref _threadId, -1);
            lock (_lock)
                return _events.ToArray();
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            // Runs from the base constructor (field initializers have run, the constructor body has not).
            if (eventSource.Name == TplEventSourceName)
                EnableEvents(eventSource, EventLevel.Verbose, TaskKeywords);
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData.EventName == null || !Recorded.Contains(eventData.EventName))
                return;
            if (Environment.CurrentManagedThreadId != Volatile.Read(ref _threadId))
                return;
            lock (_lock)
                _events.Add(eventData.EventName);
        }
    }
}
