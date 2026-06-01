package omnibox

import (
	"math"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

const (
	defaultContentMinHeight = 240
	defaultContentMaxHeight = 560
	baseVerticalPadding     = 12
	baseFieldGroupHeight    = 60
	baseActionRowHeight     = 44
	baseMessageRowHeight    = 24
	baseSectionGapHeight    = 8
)

// ContentHeightSpec describes a reusable content viewport in logical units
// rather than GTK widget pointers. It can be reused by multiple views that need
// a content area sized from the number of fields, actions, and messages.
type ContentHeightSpec struct {
	FieldGroups int
	ActionRows  int
	MessageRows int
	SectionGaps int
	MinHeight   int
	MaxHeight   int
}

// CalculateContentHeight returns the desired viewport height in pixels for the
// given content spec and UI scale, clamped into a sane range.
func CalculateContentHeight(spec ContentHeightSpec, uiScale float64) int {
	scale := normalizeUIScale(uiScale)
	minHeight := scaledOrDefault(spec.MinHeight, defaultContentMinHeight, scale)
	maxHeight := scaledOrDefault(spec.MaxHeight, defaultContentMaxHeight, scale)
	if maxHeight < minHeight {
		maxHeight = minHeight
	}

	rawHeight := baseVerticalPadding*2 +
		positive(spec.FieldGroups)*baseFieldGroupHeight +
		positive(spec.ActionRows)*baseActionRowHeight +
		positive(spec.MessageRows)*baseMessageRowHeight +
		positive(spec.SectionGaps)*baseSectionGapHeight

	return clamp(scaleInt(rawHeight, scale), minHeight, maxHeight)
}

// ItemFormContentHeight returns the desired viewport height for an item form.
func ItemFormContentHeight(itemType vault.ItemType, uiScale float64) int {
	return CalculateContentHeight(itemFormContentHeightSpec(itemType), uiScale)
}

func itemFormContentHeightSpec(itemType vault.ItemType) ContentHeightSpec {
	spec := ContentHeightSpec{
		ActionRows:  1,
		MessageRows: 1,
		SectionGaps: 2,
	}

	switch itemType {
	case vault.ItemTypeSecureNote:
		spec.FieldGroups = 2
	case vault.ItemTypeCard:
		spec.FieldGroups = 8
	case vault.ItemTypeIdentity:
		spec.FieldGroups = 10
	case vault.ItemTypeLogin:
		fallthrough
	default:
		spec.FieldGroups = 6
	}

	return spec
}

func normalizeUIScale(scale float64) float64 {
	if scale <= 0 {
		return 1
	}
	return scale
}

func scaledOrDefault(value, fallback int, scale float64) int {
	if value <= 0 {
		value = fallback
	}
	return scaleInt(value, scale)
}

func scaleInt(value int, scale float64) int {
	return int(math.Round(float64(value) * scale))
}

func positive(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
