package omnibox

import "github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"

type itemCategory int

const (
	categoryAll itemCategory = iota
	categoryLogin
	categorySecureNote
	categoryCard
	categoryIdentity
)

func categoryItemType(category itemCategory) vault.ItemType {
	switch category {
	case categorySecureNote:
		return vault.ItemTypeSecureNote
	case categoryCard:
		return vault.ItemTypeCard
	case categoryIdentity:
		return vault.ItemTypeIdentity
	default:
		return vault.ItemTypeLogin
	}
}

func categoryShortcutForMode(mode Mode, number int) (itemCategory, bool) {
	switch mode {
	case ModeSearch:
		return searchCategoryShortcut(number)
	case ModeForm:
		return formCategoryShortcut(number)
	default:
		return 0, false
	}
}

func searchCategoryShortcut(number int) (itemCategory, bool) {
	switch number {
	case 1:
		return categoryAll, true
	case 2:
		return categoryLogin, true
	case 3:
		return categorySecureNote, true
	case 4:
		return categoryCard, true
	case 5:
		return categoryIdentity, true
	default:
		return 0, false
	}
}

func formCategoryShortcut(number int) (itemCategory, bool) {
	// Add mode intentionally mirrors sekeve's visible tabs: there is no "All"
	// category when creating an item, so Ctrl+1 starts at Login.
	switch number {
	case 1:
		return categoryLogin, true
	case 2:
		return categorySecureNote, true
	case 3:
		return categoryCard, true
	case 4:
		return categoryIdentity, true
	default:
		return 0, false
	}
}
