package omnibox

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

func TestCalculateContentHeight_DefaultClamps(t *testing.T) {
	require.Equal(t, 240, CalculateContentHeight(ContentHeightSpec{}, 1))
	require.Equal(t, 560, CalculateContentHeight(ContentHeightSpec{
		FieldGroups: 20,
		ActionRows:  2,
		MessageRows: 1,
		SectionGaps: 4,
	}, 1))
}

func TestCalculateContentHeight_CustomClampRange(t *testing.T) {
	height := CalculateContentHeight(ContentHeightSpec{
		FieldGroups: 5,
		MinHeight:   300,
		MaxHeight:   320,
	}, 1)
	require.Equal(t, 320, height)
}

func TestCalculateContentHeight_ScalesWithUIScale(t *testing.T) {
	spec := ContentHeightSpec{FieldGroups: 6, ActionRows: 1, MessageRows: 1, SectionGaps: 2}
	require.Greater(t, CalculateContentHeight(spec, 1.5), CalculateContentHeight(spec, 1.0))
}

func TestItemFormContentHeight_ByItemType(t *testing.T) {
	note := ItemFormContentHeight(vault.ItemTypeSecureNote, 1)
	login := ItemFormContentHeight(vault.ItemTypeLogin, 1)
	card := ItemFormContentHeight(vault.ItemTypeCard, 1)
	identity := ItemFormContentHeight(vault.ItemTypeIdentity, 1)

	require.Equal(t, 240, note)
	require.Equal(t, 468, login)
	require.Equal(t, 560, card)
	require.Equal(t, 560, identity)
	require.Greater(t, login, note)
	require.GreaterOrEqual(t, card, login)
	require.GreaterOrEqual(t, identity, card)
}
