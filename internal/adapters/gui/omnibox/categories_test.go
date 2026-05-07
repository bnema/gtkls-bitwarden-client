package omnibox

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCategoryShortcutForMode_Search(t *testing.T) {
	tests := []struct {
		name   string
		number int
		want   itemCategory
		wantOK bool
	}{
		{name: "all", number: 1, want: categoryAll, wantOK: true},
		{name: "login", number: 2, want: categoryLogin, wantOK: true},
		{name: "note", number: 3, want: categorySecureNote, wantOK: true},
		{name: "card", number: 4, want: categoryCard, wantOK: true},
		{name: "identity", number: 5, want: categoryIdentity, wantOK: true},
		{name: "out of range", number: 6, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := categoryShortcutForMode(ModeSearch, tt.number)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCategoryShortcutForMode_FormMatchesVisibleAddTabs(t *testing.T) {
	tests := []struct {
		name   string
		number int
		want   itemCategory
		wantOK bool
	}{
		{name: "login", number: 1, want: categoryLogin, wantOK: true},
		{name: "note", number: 2, want: categorySecureNote, wantOK: true},
		{name: "card", number: 3, want: categoryCard, wantOK: true},
		{name: "identity", number: 4, want: categoryIdentity, wantOK: true},
		{name: "all is not available in add mode", number: 5, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := categoryShortcutForMode(ModeForm, tt.number)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCategoryShortcutForMode_GeneratorHasNoShortcuts(t *testing.T) {
	for i := 1; i <= 5; i++ {
		got, ok := categoryShortcutForMode(ModeGenerator, i)
		require.False(t, ok)
		require.Equal(t, itemCategory(0), got)
	}
}
