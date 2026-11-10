using Xunit;

// Disable parallel test execution across test classes in Broker.Tests to prevent
// race conditions on OS resources (Windows Named Pipes, Certificate Store, and PowerShell processes).
[assembly: CollectionBehavior(DisableTestParallelization = true)]

