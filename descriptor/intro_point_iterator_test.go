package descriptor

import (
	"reflect"
	"testing"
)

func TestSortIntroductionPoints(t *testing.T) {
	var introPoints = [][]IntroductionPoint{
		{
			{Identifier: "a1"}, {Identifier: "a2"}, {Identifier: "a3"},
			{Identifier: "a4"}, {Identifier: "a5"}, {Identifier: "a6"},
			{Identifier: "a7"}, {Identifier: "a8"},
		},
		{
			{Identifier: "b1"}, {Identifier: "b2"}, {Identifier: "b3"},
			{Identifier: "b4"}, {Identifier: "b5"}, {Identifier: "b6"},
			{Identifier: "b7"}, {Identifier: "b8"}, {Identifier: "b9"},
		},
		{
			{Identifier: "c1"}, {Identifier: "c2"}, {Identifier: "c3"},
			{Identifier: "c4"}, {Identifier: "c5"}, {Identifier: "c6"},
			{Identifier: "c7"}, {Identifier: "c8"},
		},
	}

	var want = []IntroductionPoint{
		{Identifier: "a1"}, {Identifier: "b1"}, {Identifier: "c1"}, {Identifier: "a2"},
		{Identifier: "b2"}, {Identifier: "c2"}, {Identifier: "a3"}, {Identifier: "b3"},
		{Identifier: "c3"}, {Identifier: "a4"}, {Identifier: "b4"}, {Identifier: "c4"},
		{Identifier: "a5"}, {Identifier: "b5"}, {Identifier: "c5"}, {Identifier: "a6"},
		{Identifier: "b6"}, {Identifier: "c6"}, {Identifier: "a7"}, {Identifier: "b7"},
		{Identifier: "c7"}, {Identifier: "a8"}, {Identifier: "b8"}, {Identifier: "c8"},
		{Identifier: "b9"}}

	if got := sortIntroductionPoints(introPoints); !reflect.DeepEqual(got, want) {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestIntroductionPointsIteratorNext(t *testing.T) {
	var introPoints = [][]IntroductionPoint{
		{
			{Identifier: "a1"}, {Identifier: "a2"}, {Identifier: "a3"},
			{Identifier: "a4"}, {Identifier: "a5"}, {Identifier: "a6"},
			{Identifier: "a7"}, {Identifier: "a8"},
		},
		{
			{Identifier: "b1"}, {Identifier: "b2"}, {Identifier: "b3"},
			{Identifier: "b4"}, {Identifier: "b5"}, {Identifier: "b6"},
			{Identifier: "b7"}, {Identifier: "b8"}, {Identifier: "b9"},
		},
		{
			{Identifier: "c1"}, {Identifier: "c2"}, {Identifier: "c3"},
			{Identifier: "c4"}, {Identifier: "c5"}, {Identifier: "c6"},
			{Identifier: "c7"}, {Identifier: "c8"},
		},
	}

	var itr = NewIntroductionPointsIterator(introPoints)

	var want = sortIntroductionPoints(introPoints)
	if got := itr.Next(); !reflect.DeepEqual(got, want[0:10]) {
		t.Errorf("expected %v got %v", want, got)
	}

	if got := itr.Next(); !reflect.DeepEqual(got, want[10:20]) {
		t.Errorf("expected %v got %v", want, got)
	}

	want = append(want[20:], want[:5]...)
	if got := itr.Next(); !reflect.DeepEqual(got, want) {
		t.Errorf("expected %v got %v", want, got)
	}
}
