package adaptive

type failedAttemptsRule struct{}

// NewFailedAttemptsRule returns the v1 failed attempts adaptive rule.
func NewFailedAttemptsRule() Rule { return failedAttemptsRule{} }

func (failedAttemptsRule) Name() string { return "failed_attempts" }

func (failedAttemptsRule) Evaluate(ctx Context, cfg Config) (bool, string) {
	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = DefaultFailureThreshold
	}
	if ctx.FailedAttempts < threshold {
		return false, ""
	}
	return true, "failed attempts threshold exceeded"
}
