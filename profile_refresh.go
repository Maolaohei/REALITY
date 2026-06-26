package reality

// This file is kept for backward compatibility.
// All refresh logic has been moved to refresh_manager.go.
//
// The old BackgroundRefreshManager with per-target goroutines has been
// replaced by RefreshManager which uses a single scheduler goroutine.
