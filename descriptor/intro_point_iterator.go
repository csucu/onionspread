package descriptor

// IntroductionPointsIterator is a stateful iterator for introduction points
type IntroductionPointsIterator struct {
	introductionPoints []IntroductionPointV2

	currentPos int
}

// sortIntroductionPoints sorts introduction points in a round robin fashion given a set of
// introduction points per backend instance.
func sortIntroductionPoints(backendIntroductionPoints [][]IntroductionPointV2) []IntroductionPointV2 {
	var introductionPoints []IntroductionPointV2

	// get max len
	var maxLen = 0
	for _, introductionPoints := range backendIntroductionPoints {
		var len = len(introductionPoints)
		if len > maxLen {
			maxLen = len
		}

	}

	// sort all the introduction points from the diffrent backend instances in a round robin fashioned
	for i := 0; i < maxLen; i++ {
		for j := 0; j < len(backendIntroductionPoints); j++ {
			if len(backendIntroductionPoints[j]) > i {
				introductionPoints = append(introductionPoints, backendIntroductionPoints[j][i])
			}
		}
	}

	return introductionPoints
}

// Next returns the next IntroductionPointV2 in the cycle
func (ips *IntroductionPointsIterator) Next() []IntroductionPointV2 {
	var start = ips.currentPos
	var len = len(ips.introductionPoints)

	ips.currentPos = ips.currentPos + 10
	if ips.currentPos <= len {
		return ips.introductionPoints[start:ips.currentPos]
	}

	var next = ips.introductionPoints[start:len]

	ips.currentPos = ips.currentPos % len
	next = append(next, ips.introductionPoints[0:ips.currentPos]...)

	return next
}

// NewIntroductionPointsIterator returns a new NewIntroductionPointsIterator
func NewIntroductionPointsIterator(introductionPoints [][]IntroductionPointV2) *IntroductionPointsIterator {
	return &IntroductionPointsIterator{
		currentPos:         0,
		introductionPoints: sortIntroductionPoints(introductionPoints),
	}
}
